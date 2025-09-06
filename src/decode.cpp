/*
 * GitZipQR.cpp – Decoder
 * Author: Daniil V (RestlessByte)[https://github.com/RestlessByte]
 * License: MIT
 *
 * Reads PNG QR codes, reconstructs encrypted chunks, verifies SHA256, and
 * decrypts via AES-256-GCM to the original file/zip.
 */

#include "common.hpp"
#include "config.hpp"
#include "third_party/json.hpp"

#include <ZXing/ReadBarcode.h>
#include <ZXing/BarcodeFormat.h>
#include <ZXing/ReaderOptions.h>
#include <png.h>
#include <filesystem>
#include <map>
#include <vector>
#include <iostream>

using namespace gzqr;
using mini_json::value;

// ---------------- PNG reader ----------------
static std::vector<uint8_t> png_rgba(const std::string& p, int& w, int& h){
  FILE* fp=fopen(p.c_str(),"rb"); if(!fp) throw std::runtime_error("open png");
  png_structp png_ptr=png_create_read_struct(PNG_LIBPNG_VER_STRING,nullptr,nullptr,nullptr);
  if(!png_ptr){ fclose(fp); throw std::runtime_error("png_read_struct"); }
  png_infop info_ptr=png_create_info_struct(png_ptr);
  if(!info_ptr){ png_destroy_read_struct(&png_ptr,nullptr,nullptr); fclose(fp); throw std::runtime_error("png_info_struct"); }
  if(setjmp(png_jmpbuf(png_ptr))){ png_destroy_read_struct(&png_ptr,&info_ptr,nullptr); fclose(fp); throw std::runtime_error("png read"); }
  png_init_io(png_ptr, fp); png_read_info(png_ptr, info_ptr);
  w=png_get_image_width(png_ptr,info_ptr); h=png_get_image_height(png_ptr,info_ptr);
  png_byte ct=png_get_color_type(png_ptr,info_ptr), bd=png_get_bit_depth(png_ptr,info_ptr);
  if(bd==16) png_set_strip_16(png_ptr);
  if(ct==PNG_COLOR_TYPE_PALETTE) png_set_palette_to_rgb(png_ptr);
  if(ct==PNG_COLOR_TYPE_GRAY && bd<8) png_set_expand_gray_1_2_4_to_8(png_ptr);
  if(png_get_valid(png_ptr,info_ptr,PNG_INFO_tRNS)) png_set_tRNS_to_alpha(png_ptr);
  if(ct==PNG_COLOR_TYPE_RGB || ct==PNG_COLOR_TYPE_GRAY || ct==PNG_COLOR_TYPE_PALETTE) png_set_filler(png_ptr,0xFF,PNG_FILLER_AFTER);
  if(ct==PNG_COLOR_TYPE_GRAY || ct==PNG_COLOR_TYPE_GRAY_ALPHA) png_set_gray_to_rgb(png_ptr);
  png_read_update_info(png_ptr, info_ptr);
  std::vector<uint8_t> img((size_t)w*h*4); std::vector<png_bytep> rows(h);
  for(int y=0;y<h;y++) rows[y]=img.data()+ (size_t)y*w*4;
  png_read_image(png_ptr, rows.data());
  png_destroy_read_struct(&png_ptr,&info_ptr,nullptr); fclose(fp); return img;
}

// ---------------- QR decode ----------------
static std::string decode_qr(const std::string& path){
  int w=0,h=0; auto rgba=png_rgba(path,w,h);
  ZXing::ImageView iv(rgba.data(),w,h,ZXing::ImageFormat::RGBA);
  ZXing::ReaderOptions opts; opts.setFormats(ZXing::BarcodeFormat::QRCode);
  auto res = ZXing::ReadBarcode(iv, opts);
  return res.isValid()? res.text() : "";
}

// ---------------- Main ----------------
int main(int argc, char** argv){
  if(argc<2){ std::fprintf(stderr,"Usage: MakeDecode <qrs_dir> [out_dir]\n"); return 2; }
  try{
    std::string indir=argv[1], outdir=(argc>=3?argv[2]:"out");
    std::filesystem::create_directories(outdir);

    std::fprintf(stdout,"STEP #1 collect data ... ");
    std::vector<std::string> files;
    for(auto& e: std::filesystem::directory_iterator(indir))
      if(e.is_regular_file() && e.path().extension()==".png") files.push_back(e.path().string());
    if(files.empty()){ std::fprintf(stdout,"[0]\n"); throw std::runtime_error("No QR images"); }
    std::fprintf(stdout,"[%zu]\n",files.size());

    std::string nameBase="restored", metaExt, cipherSha;
    std::vector<uint8_t> salt, nonce;
    int expectedTotal=-1, chunkSize=0;
    std::map<int,std::vector<uint8_t>> chunks;

    for(auto& f: files){
      auto txt=decode_qr(f); if(txt.empty()) continue;
      auto j=value::parse(txt);
      if(!j.contains("type")) continue;
      if(j["type"].get<std::string>()!=std::string(gzqr_config::kProjectName)+"-CHUNK-ENC") continue;

      int chunk=(int)j["chunk"].get<double>();
      int total=(int)j["total"].get<double>();
      auto data=b64d(j["dataB64"].get<std::string>());
      if(sha256_hex(data)!=j["hash"].get<std::string>()) continue;

      if(expectedTotal<0) expectedTotal=total;
      if(chunkSize==0) chunkSize=(int)j["chunkSize"].get<double>();
      if(cipherSha.empty()) cipherSha=j["cipherHash"].get<std::string>();
      if(salt.empty()) salt=b64d(j["saltB64"].get<std::string>());
      if(nonce.empty()) nonce=b64d(j["nonceB64"].get<std::string>());
      if(nameBase=="restored" && j.contains("name")) nameBase=j["name"].get<std::string>();
      if(metaExt.empty() && j.contains("ext")) metaExt=j["ext"].get<std::string>();

      chunks[chunk]=data;
      if(gzqr_config::kPrintProgressCounters)
        std::fprintf(stdout,"   collected chunk %d/%d\n",chunk+1,total);
    }

    if((int)chunks.size()!=expectedTotal) throw std::runtime_error("Missing chunks");

    std::string cipherFile=(std::filesystem::temp_directory_path()/ "gzqr-cipher.bin").string();
    FILE* fc=fopen(cipherFile.c_str(),"wb");
    for(auto& [i,d]:chunks) fwrite(d.data(),1,d.size(),fc);
    fclose(fc);

    if(sha256_hex_file(cipherFile)!=cipherSha) throw std::runtime_error("Global sha256 mismatch");

    std::fprintf(stdout,"STEP #3 decrypt ... ");
    std::string pass = std::getenv("GZQR_PASS") ? std::getenv("GZQR_PASS") : std::string(gzqr_config::kDefaultPassword);
    if(pass.size()<8) throw std::runtime_error("Password >=8 required");
    auto key=scrypt_kdf(pass,salt,{(1u<<15),8u,(uint32_t)std::max(1u,std::thread::hardware_concurrency())});

    std::string outName=(nameBase.empty()?std::string("restored"):nameBase)+(metaExt.empty()?"":metaExt);
    std::string outPath=(std::filesystem::path(outdir)/outName).string();
    aes_gcm_decrypt_file_to_path(cipherFile,outPath,key,nonce,{});
    std::fprintf(stdout,"[1]\nSTEP #4 write output ... [1]\n");
    std::filesystem::remove(cipherFile);

    std::printf("\n✅ Restored file → %s\n", outPath.c_str());
    return 0;
  }catch(const std::exception& e){
    std::fprintf(stderr,"Error: %s\n",e.what()); return 1;
  }
}
