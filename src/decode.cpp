#include "common.hpp"
#include "third_party/json.hpp"
#include <ZXing/ReadBarcode.h>
#include <ZXing/Barcode.h>

#include <ZXing/BarcodeFormat.h>
#include <ZXing/ReaderOptions.h>
#include <png.h>
#include <filesystem>
#include <map>
#include <mutex>
#include <thread>
#include <atomic>
#include <iostream>
using namespace gzqr; using mini_json::value;
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
  std::vector<uint8_t> img(w*h*4); std::vector<png_bytep> rows(h);
  for(int y=0;y<h;y++) rows[y]=img.data()+y*w*4; png_read_image(png_ptr, rows.data());
  png_destroy_read_struct(&png_ptr,&info_ptr,nullptr); fclose(fp); return img;
}
static std::string decode_qr(const std::string& path){
  int w=0,h=0; auto rgba=png_rgba(path,w,h);
  ZXing::ImageView iv(rgba.data(),w,h,ZXing::ImageFormat::RGBA);
  ZXing::ReaderOptions opts; opts.setFormats(ZXing::BarcodeFormat::QRCode); auto res = ZXing::ReadBarcode(iv, opts);
  if(!res.isValid()) return std::string(); return res.text();
}
int main(int argc, char** argv){
  if(argc<2){ std::fprintf(stderr,"Usage: MakeDecode <qrcodes_dir> [output_dir]\n"); return 2; }
  std::string in = argv[1]; std::string outdir = argc>=3? argv[2] : std::filesystem::current_path().string();
  std::filesystem::create_directories(outdir);
  try{
    std::fprintf(stdout,"STEP #1 collect data ... ");
    std::vector<std::string> files;
    for(auto& e: std::filesystem::directory_iterator(in)){
      if(!e.is_regular_file()) continue;
      auto ext=e.path().extension().string(); for(auto& c:ext) c=std::tolower(c);
      if(ext==".png"||ext==".jpg"||ext==".jpeg") files.push_back(e.path().string());
    }
    if(files.empty()){ std::fprintf(stdout,"[0]\n"); throw std::runtime_error("No QR images"); }
    std::map<int,std::vector<uint8_t>> chunks;
    std::string nameBase, metaExt, cipherSha; KDFParams kdf{(1u<<15),8u,(uint32_t)std::max(1u,std::thread::hardware_concurrency())};
    std::vector<uint8_t> salt, nonce; int expectedTotal=-1;
    std::mutex m; std::atomic<int> idx{0};
    auto worker=[&](){
      int i; while((i=idx++)<(int)files.size()){
        auto txt = decode_qr(files[i]); if(txt.empty()) continue;
        try{
          auto j = mini_json::value::parse(txt);
          if(!j.contains("type")||j["type"].get<std::string>()!="GitZipQR-CHUNK-ENC") continue;
          int chunk=(int)j["chunk"].get<double>(), total=(int)j["total"].get<double>();
          auto data=b64d(j["dataB64"].get<std::string>()); if(sha256_hex(data)!=j["hash"].get<std::string>()) continue;
          std::lock_guard<std::mutex> lk(m);
          chunks[chunk]=std::move(data);
          if(nameBase.empty()&&j.contains("name")) nameBase=j["name"].get<std::string>();
          if(metaExt.empty() &&j.contains("ext"))  metaExt=j["ext"].get<std::string>();
          if(cipherSha.empty()&&j.contains("cipherHash")) cipherSha=j["cipherHash"].get<std::string>();
          if(salt.empty()&&j.contains("saltB64")) salt=b64d(j["saltB64"].get<std::string>());
          if(nonce.empty()&&j.contains("nonceB64")) nonce=b64d(j["nonceB64"].get<std::string>());
          if(expectedTotal<0) expectedTotal=total;
        }catch(...){}
      }
    };
    int T=std::max(1u,std::thread::hardware_concurrency()); std::vector<std::thread> th;
    for(int t=0;t<T;t++) th.emplace_back(worker); for(auto&x:th) x.join();
    if(expectedTotal<=0 || (int)chunks.size()!=expectedTotal) throw std::runtime_error("Missing chunks");
    std::vector<uint8_t> cipher; cipher.reserve((size_t)expectedTotal*1400);
    for(int i=0;i<expectedTotal;i++){ if(!chunks.count(i)) throw std::runtime_error("Gap"); auto& c=chunks[i]; cipher.insert(cipher.end(),c.begin(),c.end()); }
    if(!cipherSha.empty() && sha256_hex(cipher)!=cipherSha) throw std::runtime_error("Global sha256 mismatch");
    std::fprintf(stdout,"[1]\n");
    std::fprintf(stdout,"STEP #3 decrypt ... ");
    if(salt.empty()||nonce.empty()) throw std::runtime_error("Crypto params missing");
    std::string pass; { const char* pf=getenv("GZQR_PASSFILE");
      if(pf && *pf) pass=prompt_hidden("");
      else{ std::string cnt; std::fprintf(stdout,"AMOUNT NUMBER OF PASSWORD: "); std::getline(std::cin,cnt);
        int n=2; try{ n=std::max(1, std::stoi(cnt)); }catch(...){}
        std::vector<std::string> parts; for(int i=1;i<=n;i++){ auto p=prompt_hidden("Password #"+std::to_string(i)+": "); if(p.size()<8) throw std::runtime_error("Password >=8"); parts.push_back(p); }
        pass=join_passwords(parts); } }
    mini_json::value aad_obj(std::map<std::string,mini_json::value>{{"version","4.0-cpp-inline"},{"name",nameBase},{"ext",metaExt},{"N",(double)kdf.N},{"r",(double)kdf.r},{"p",(double)kdf.p}});
    std::string aad_s=aad_obj.dump(); std::vector<uint8_t> aad(aad_s.begin(),aad_s.end());
    auto key = scrypt_kdf(pass, salt, kdf); auto plain = aes_gcm_decrypt_mem(cipher, key, nonce, aad); std::fprintf(stdout,"[1]\n");
    std::fprintf(stdout,"STEP #4 write output ... ");
    std::string outName = nameBase + (metaExt.empty()? "" : metaExt); std::string outPath = (std::filesystem::path(outdir)/outName).string();
    write_all(outPath, plain); std::fprintf(stdout,"[1]\n");
    if(const char* usdt=getenv("USDT_ADDRESS"); usdt&&*usdt) std::printf("Support me please USDT money - %s\n", usdt);
    if(!metaExt.empty() && metaExt==".zip") std::printf("\n✅ Restored ZIP → %s\n", outPath.c_str()); else std::printf("\n✅ Restored file → %s\n", outPath.c_str());
    return 0;
  } catch(const std::exception& e){ std::fprintf(stderr,"Error: %s\n", e.what()); return 1; }
}
