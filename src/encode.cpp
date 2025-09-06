#include "common.hpp"
#include "third_party/json.hpp"
#include <filesystem>
#include <thread>
#include <atomic>
#include <mutex>
#include <iostream>

using namespace gzqr;
using mini_json::value;

static bool is_dir(const std::string& p){ return std::filesystem::is_directory(p); }
static std::string tmpfile(const std::string& prefix){ return (std::filesystem::temp_directory_path()/(prefix+std::to_string(std::rand()))).string(); }
static std::string materialize_data(const std::string& input, std::string& nameBase, std::string& metaExt){
  if(is_dir(input)){
    nameBase = std::filesystem::path(input).filename().string();
    metaExt = ".zip";
    std::string out = tmpfile("gzqr-") + ".zip";
    std::string cmd = "zip -r -q '" + out + "' '" + input + "'";
    if(std::system(cmd.c_str())!=0) throw std::runtime_error("zip failed (install zip)");
    return out;
  } else {
    auto p = std::filesystem::path(input);
    metaExt = p.has_extension()? p.extension().string() : std::string();
    nameBase = metaExt.empty()? p.filename().string() : p.stem().string();
    return input;
  }
}
static void save_qr_png(const std::string& out, const std::string& text, int margin=1, int scale=8){
  std::string tmp = tmpfile("payload-") + ".txt";
  { FILE*f=fopen(tmp.c_str(),"wb"); if(!f) throw std::runtime_error("tmp"); fwrite(text.data(),1,text.size(),f); fclose(f); }
  std::string cmd = "qrencode -o '" + out + "' -l Q -m " + std::to_string(margin) + " -s " + std::to_string(scale) + " < '" + tmp + "'";
  int rc = std::system(cmd.c_str()); std::filesystem::remove(tmp);
  if(rc!=0) throw std::runtime_error("qrencode failed (install libqrencode/qrencode)");
}
int main(int argc, char** argv){
  if(argc<2){ std::fprintf(stderr,"Usage: MakeEncode <input_file_or_dir> [output_dir]\n"); return 2; }
  std::srand((unsigned)time(nullptr));
  std::string input = argv[1];
  std::string outdir = argc>=3? argv[2] : "qrcodes";
  std::filesystem::create_directories(outdir);
  try{
    std::string pass;
    { const char* pf = std::getenv("GZQR_PASSFILE");
      if(pf && *pf) pass = prompt_hidden("");
      else {
        std::string cnt; std::fprintf(stdout,"AMOUNT NUMBER OF PASSWORD: "); std::getline(std::cin,cnt);
        int n=2; try{ n=std::max(1, std::stoi(cnt)); }catch(...){}
        std::vector<std::string> parts;
        for(int i=1;i<=n;i++){ auto p=prompt_hidden("Password #"+std::to_string(i)+": "); if(p.size()<8) throw std::runtime_error("Password >=8"); parts.push_back(p); }
        pass = join_passwords(parts);
      } }
    std::fprintf(stdout,"STEP #2 prepare data ... ");
    std::string nameBase, metaExt; std::string dataPath = materialize_data(input, nameBase, metaExt); std::fprintf(stdout,"[1]\n");
    std::fprintf(stdout,"STEP #3 encrypt ... ");
    std::vector<uint8_t> salt(16), nonce(12); RAND_bytes(salt.data(),16); RAND_bytes(nonce.data(),12);
    KDFParams kdf{ (1u<<15), 8u, (uint32_t)std::max(1u, std::thread::hardware_concurrency()) };
    auto key = scrypt_kdf(pass, salt, kdf);
    value aad_obj(std::map<std::string,value>{{"version","4.0-cpp-inline"},{"name",nameBase},{"ext",metaExt},{"N",(double)kdf.N},{"r",(double)kdf.r},{"p",(double)kdf.p}});
    std::string aad_str = aad_obj.dump(); std::vector<uint8_t> aad(aad_str.begin(), aad_str.end());
    std::string encPath = tmpfile("payload-") + ".enc"; aes_gcm_encrypt_file(dataPath, encPath, key, nonce, aad);
    std::string cipherSha = sha256_hex_file(encPath); std::fprintf(stdout,"[1]\n");
    std::fprintf(stdout,"STEP #4 chunk & encode QR ... \n");
    const int CHUNK_SIZE = 1400;
    FILE* f=fopen(encPath.c_str(),"rb"); if(!f) throw std::runtime_error("open enc"); fseek(f,0,SEEK_END); long sz=ftell(f); fseek(f,0,SEEK_SET);
    int total = (int)((sz + CHUNK_SIZE - 1)/CHUNK_SIZE); std::vector<std::vector<uint8_t>> chunks(total);
    for(int i=0;i<total;i++){ size_t s=(size_t)i*CHUNK_SIZE; size_t len=std::min((size_t)CHUNK_SIZE,(size_t)sz-s); chunks[i].resize(len); if(len) fread(chunks[i].data(),1,len,f); } fclose(f);
    auto fileId = sha256_hex(std::vector<uint8_t>(nameBase.begin(),nameBase.end())).substr(0,16);
    std::atomic<int> done{0}; std::mutex io;
    auto do_one = [&](int i){
      auto &buf=chunks[i];
      value meta(std::map<std::string,value>{
        {"type","GitZipQR-CHUNK-ENC"},{"version","4.0-cpp-inline"},{"fileId",fileId},{"name",nameBase},{"ext",metaExt},
        {"chunk",(double)i},{"total",(double)total},{"hash",sha256_hex(buf)},{"cipherHash",cipherSha},
        {"kdfParams", std::map<std::string,value>{{"N",(double)kdf.N},{"r",(double)kdf.r},{"p",(double)kdf.p}}},
        {"saltB64", b64(salt)}, {"nonceB64", b64(nonce)}, {"chunkSize",(double)CHUNK_SIZE},{"dataB64", b64(buf)}
      });
      std::string payload = meta.dump(); char fn[64]; std::snprintf(fn,sizeof(fn),"qr-%06d.png", i);
      save_qr_png((std::filesystem::path(outdir)/fn).string(), payload, 1, 8);
      int d=++done; if(d%25==0||d==total){ std::lock_guard<std::mutex>lk(io); std::fprintf(stdout,"  QR %d/%d\r", d,total); std::fflush(stdout); }
    };
    int T = std::max(1u,std::thread::hardware_concurrency()); std::atomic<int> idx{0}; std::vector<std::thread> th;
    auto worker=[&](){ int i; while((i=idx++)<total) do_one(i); };
    for(int t=0;t<T;t++) th.emplace_back(worker); for(auto&x:th) x.join(); std::fprintf(stdout,"\n[1]\n");
    std::printf("\nDone.\nQRCodes:    %s\nFileID:     %s\nChunks:     %d\n", outdir.c_str(), fileId.c_str(), total);
    if(const char* usdt=getenv("USDT_ADDRESS"); usdt&&*usdt) std::printf("Support me please USDT money - %s\n", usdt);
    return 0;
  } catch(const std::exception& e){ std::fprintf(stderr,"Error: %s\n", e.what()); return 1; }
}
