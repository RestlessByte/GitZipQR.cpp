/*
 * GitZipQR.cpp – Encoder
 * Author: Daniil V (RestlessByte)[https://github.com/RestlessByte]
 * License: MIT
 *
 * Archives (if a directory), encrypts via AES-256-GCM (key from scrypt),
 * splits the encrypted bytes into multiple QR code PNGs.
 *
 * IMPORTANT: Chunk sizing is calibrated against the ACTUAL JSON payload
 * (including base64 + metadata), so "Payload > QR capacity" won't happen.
 */

#include "common.hpp"
#include "config.hpp"
#include "third_party/json.hpp"

#include <filesystem>
#include <thread>
#include <iostream>
#include <cstdlib>
#include <map>
#include <vector>
#include <algorithm>
#include <qrencode.h>
#include <png.h>

using namespace gzqr;
using mini_json::value;

// ---------------- Helpers ----------------
static bool is_dir(const std::string& p){ return std::filesystem::is_directory(p); }
static std::string tmpfile(const std::string& prefix){
  return (std::filesystem::temp_directory_path()/(prefix+std::to_string(std::rand()))).string();
}
static int qr_version(){ return gzqr_config::kDefaultQRVersion; }
static int qr_margin(){  return gzqr_config::kDefaultQRMargin; }
static int qr_scale(){   return gzqr_config::kDefaultQRScale; }
static int qr_ecl(){
  char c=gzqr_config::kDefaultQRECL;
  switch(c){ case 'L': return QR_ECLEVEL_L; case 'M': return QR_ECLEVEL_M; case 'H': return QR_ECLEVEL_H; default: return QR_ECLEVEL_Q; }
}

// ---------------- Zip input ----------------
// NOTE: when input is a directory, we (cd) into it and zip "." so the ZIP root
// contains only the directory contents (no "home/.../folder/" prefix).
static std::string materialize_data(const std::string& input,std::string& nameBase,std::string& metaExt){
  if(is_dir(input)){
    auto p=std::filesystem::path(input);
    std::string base=p.filename().string();
    if(base.empty()) base=p.parent_path().filename().string();
    nameBase=base;
    metaExt=".zip";

    std::string out=tmpfile("gzqr-")+".zip";
    std::string cmd = std::string("(cd '") + input + "' && zip -r -q '" + out + "' .)";
    if(std::system(cmd.c_str())!=0) throw std::runtime_error("zip failed (install zip)");
    return out;
  } else {
    auto p=std::filesystem::path(input);
    metaExt=p.has_extension()?p.extension().string():"";
    nameBase=metaExt.empty()?p.filename().string():p.stem().string();
    return input;
  }
}

// ---------------- PNG writer ----------------
static void write_qr_png(const std::string& out,QRcode* qrcode,int margin,int scale){
  if(!qrcode) throw std::runtime_error("QRcode is null");
  const int qsize=qrcode->width;
  const int img_size=(qsize+2*margin)*scale;
  std::vector<uint8_t> rgba((size_t)img_size*img_size*4,0xFF);
  auto set_px=[&](int x,int y,uint8_t v){
    if(x<0||y<0||x>=img_size||y>=img_size) return;
    size_t off=((size_t)y*img_size+x)*4;
    rgba[off]=v; rgba[off+1]=v; rgba[off+2]=v; rgba[off+3]=0xFF;
  };
  const unsigned char* data=qrcode->data;
  for(int my=0;my<qsize;++my){
    for(int mx=0;mx<qsize;++mx){
      bool dark=(data[my*qsize+mx]&1)!=0;
      uint8_t v=dark?0:255;
      int px0=(margin+mx)*scale,py0=(margin+my)*scale;
      for(int dy=0;dy<scale;dy++) for(int dx=0;dx<scale;dx++) set_px(px0+dx,py0+dy,v);
    }
  }
  FILE* fp=fopen(out.c_str(),"wb"); if(!fp) throw std::runtime_error("open png");
  png_structp png_ptr=png_create_write_struct(PNG_LIBPNG_VER_STRING,nullptr,nullptr,nullptr);
  png_infop info_ptr=png_create_info_struct(png_ptr);
  if(setjmp(png_jmpbuf(png_ptr))){ png_destroy_write_struct(&png_ptr,&info_ptr); fclose(fp); throw std::runtime_error("png write"); }
  png_init_io(png_ptr,fp);
  png_set_IHDR(png_ptr,info_ptr,img_size,img_size,8,PNG_COLOR_TYPE_RGBA,PNG_INTERLACE_NONE,PNG_COMPRESSION_TYPE_DEFAULT,PNG_FILTER_TYPE_DEFAULT);
  png_write_info(png_ptr,info_ptr);
  std::vector<png_bytep> rows(img_size); for(int y=0;y<img_size;y++) rows[y]=(png_bytep)&rgba[(size_t)y*img_size*4];
  png_write_image(png_ptr,rows.data()); png_write_end(png_ptr,nullptr);
  png_destroy_write_struct(&png_ptr,&info_ptr); fclose(fp);
}

// ---------------- Capacity probing ----------------
static bool payload_fits(const std::string& payload,int version,int ecl){
  QRcode* q=QRcode_encodeData((int)payload.size(),(const unsigned char*)payload.data(),version,(QRecLevel)ecl);
  if(!q) return false; QRcode_free(q); return true;
}

/*
 * Realistic capacity calibration:
 * Build payload identical to real one and probe the QR capacity.
 */
static int max_data_bytes_per_chunk(int version,int ecl,
                                    const std::string& nameBase,
                                    const std::string& metaExt)
{
  const std::string type = std::string(gzqr_config::kProjectName) + "-CHUNK-ENC";
  const std::string projVer = gzqr_config::kProjectVersion;
  const std::string fakeCipherSha(64,'0');
  const std::vector<uint8_t> fakeSalt(16, 0x11);
  const std::vector<uint8_t> fakeNonce(12,0x22);
  const std::string saltB64 = b64(fakeSalt);
  const std::string nonceB64= b64(fakeNonce);
  const int worstChunk = 999999;
  const int worstTotal = 999999;
  const int worstChunkSize = 999999;

  int lo = 32, hi = 1<<16;
  auto fits = [&](int dataBytes)->bool{
    std::vector<uint8_t> data((size_t)dataBytes, 0x41);
    std::map<std::string,mini_json::value> meta;
    meta["type"]       = type;
    meta["version"]    = projVer;
    meta["chunk"]      = (double)worstChunk;
    meta["total"]      = (double)worstTotal;
    meta["hash"]       = std::string(64,'0');
    meta["cipherHash"] = fakeCipherSha;
    meta["saltB64"]    = saltB64;
    meta["nonceB64"]   = nonceB64;
    meta["name"]       = nameBase;
    meta["ext"]        = metaExt;
    meta["chunkSize"]  = (double)worstChunkSize;
    meta["dataB64"]    = b64(data);
    std::string payload = mini_json::value(meta).dump();
    return payload_fits(payload, version, ecl);
  };
  while(lo < hi){
    int mid = (lo + hi + 1)/2;
    if(fits(mid)) lo = mid; else hi = mid - 1;
  }
  return std::max(16, lo - 16); // safety headroom
}

// ---------------- Main ----------------
int main(int argc,char** argv){
  if(argc<2){ std::fprintf(stderr,"Usage: MakeEncode <input_file_or_dir> [output_dir]\n"); return 2; }
  try{
    std::srand((unsigned)time(nullptr));
    std::string input=argv[1];
    std::string outdir=argc>=3?argv[2]:"qrcodes";
    std::filesystem::create_directories(outdir);

    // 1) Password (from config; override with GZQR_PASS if set)
    std::string pass = std::getenv("GZQR_PASS") ? std::getenv("GZQR_PASS") : std::string(gzqr_config::kDefaultPassword);
    if(pass.size()<8) throw std::runtime_error("Password >=8 required");

    // 2) Prepare data
    std::fprintf(stdout,"STEP #2 prepare data ... ");
    std::string nameBase,metaExt; std::string dataPath=materialize_data(input,nameBase,metaExt);
    std::fprintf(stdout,"[1]\n");

    // 3) Encrypt
    std::fprintf(stdout,"STEP #3 encrypt ... ");
    std::vector<uint8_t> salt(16),nonce(12); RAND_bytes(salt.data(),16); RAND_bytes(nonce.data(),12);
    KDFParams kdf{(1u<<15),8u,(uint32_t)std::max(1u,std::thread::hardware_concurrency())};
    auto key=scrypt_kdf(pass,salt,kdf);
    std::string encPath=tmpfile("payload-")+".enc"; aes_gcm_encrypt_file(dataPath,encPath,key,nonce,{});
    std::string cipherSha=sha256_hex_file(encPath); std::fprintf(stdout,"[1]\n");

    // 4) Chunk & Encode
    const int ECL=qr_ecl(),QVER=qr_version(),MARGIN=qr_margin(),SCALE=qr_scale();
    FILE* f=fopen(encPath.c_str(),"rb"); if(!f) throw std::runtime_error("open enc");
    fseek(f,0,SEEK_END); long sz=ftell(f); fseek(f,0,SEEK_SET);

    int chunk_size = max_data_bytes_per_chunk(QVER,ECL,nameBase,metaExt);
    if(chunk_size < 64) chunk_size = 64;
    int total=(int)((sz+chunk_size-1)/chunk_size);

    std::fprintf(stdout,"STEP #4 chunk & encode QR ... (chunkSize=%d total=%d)\n",chunk_size,total);
    std::vector<uint8_t> buf(chunk_size);

    for(int i=0;i<total;i++){
      size_t rd=fread(buf.data(),1,chunk_size,f);
      std::vector<uint8_t> view(buf.begin(),buf.begin()+rd);

      std::map<std::string,value> meta;
      meta["type"]=std::string(gzqr_config::kProjectName)+"-CHUNK-ENC";
      meta["version"]=gzqr_config::kProjectVersion;
      meta["chunk"]=(double)i;
      meta["total"]=(double)total;
      meta["hash"]=sha256_hex(view);
      meta["cipherHash"]=cipherSha;
      meta["saltB64"]=b64(salt);
      meta["nonceB64"]=b64(nonce);
      meta["name"]=nameBase;
      meta["ext"]=metaExt;
      meta["chunkSize"]=(double)chunk_size;
      meta["dataB64"]=b64(view);

      std::string payload=value(meta).dump();
      if(!payload_fits(payload,QVER,ECL)){ fclose(f); throw std::runtime_error("Internal error: calibrated payload did not fit"); }

      char fn[64]; std::snprintf(fn,sizeof(fn),"qr-%06d.png",i);
      QRcode* q=QRcode_encodeString(payload.c_str(),QVER,(QRecLevel)ECL,QR_MODE_8,1);
      write_qr_png((std::filesystem::path(outdir)/fn).string(),q,MARGIN,SCALE);
      QRcode_free(q);

      if(gzqr_config::kPrintProgressCounters)
        std::fprintf(stdout,"   chunk %d/%d written\n",i+1,total);
    }
    fclose(f);
    std::printf("\n✅ Done. Chunks: %d → %s\n",total,outdir.c_str());
    return 0;
  }catch(const std::exception& e){
    std::fprintf(stderr,"Error: %s\n",e.what()); return 1;
  }
}
