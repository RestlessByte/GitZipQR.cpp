#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <filesystem>
#include <stdexcept>
#include <cstdio>
#include <cstdlib>
#include <thread>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <termios.h>
#include <iostream>
#include <unistd.h>
namespace gzqr {
struct KDFParams { uint64_t N; uint32_t r; uint32_t p; };
inline std::string sha256_hex(const std::vector<uint8_t>& buf){ unsigned char h[32]; SHA256(buf.data(), buf.size(), h);
  static const char* X="0123456789abcdef"; std::string s(64,'0'); for(int i=0;i<32;i++){ s[2*i]=X[(h[i]>>4)&15]; s[2*i+1]=X[h[i]&15]; } return s; }
inline std::string sha256_hex_file(const std::string& path){ FILE* f=fopen(path.c_str(),"rb"); if(!f) throw std::runtime_error("open sha256");
  SHA256_CTX c; SHA256_Init(&c); std::vector<uint8_t>b(1<<20); size_t n; while((n=fread(b.data(),1,b.size(),f))>0) SHA256_Update(&c,b.data(),n);
  fclose(f); unsigned char h[32]; SHA256_Final(h,&c); static const char* X="0123456789abcdef"; std::string s(64,'0'); for(int i=0;i<32;i++){ s[2*i]=X[(h[i]>>4)&15]; s[2*i+1]=X[h[i]&15]; } return s; }
inline std::string b64(const std::vector<uint8_t>& in){ static const char* t="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string o; o.reserve(((in.size()+2)/3)*4); size_t i=0; while(i+3<=in.size()){ uint32_t v=(in[i]<<16)|(in[i+1]<<8)|in[i+2]; i+=3;
    o.push_back(t[(v>>18)&63]); o.push_back(t[(v>>12)&63]); o.push_back(t[(v>>6)&63]); o.push_back(t[v&63]); }
  if(i+1==in.size()){ uint32_t v=(in[i]<<16); o.push_back(t[(v>>18)&63]); o.push_back(t[(v>>12)&63]); o.push_back('='); o.push_back('='); }
  else if(i+2==in.size()){ uint32_t v=(in[i]<<16)|(in[i+1]<<8); o.push_back(t[(v>>18)&63]); o.push_back(t[(v>>12)&63]); o.push_back(t[(v>>6)&63]); o.push_back('='); }
  return o; }
inline std::vector<uint8_t> b64d(const std::string& s){ int T[256]; for(int i=0;i<256;i++) T[i]=-1; std::string tab="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  for(int i=0;i<64;i++) T[(unsigned char)tab[i]]=i; std::vector<uint8_t> o; o.reserve(s.size()*3/4);
  int val=0,valb=-8; for(unsigned char c:s){ if(T[c]==-1){ if(c=='=') break; else continue; } val=(val<<6)+T[c]; valb+=6; if(valb>=0){ o.push_back((uint8_t)((val>>valb)&255)); valb-=8; } } return o; }
inline std::string join_passwords(const std::vector<std::string>& parts){ std::string r; for(size_t i=0;i<parts.size();++i){ if(i) r.push_back('\0'); r+=parts[i]; } return r; }
inline std::string prompt_hidden(const std::string& label){ const char* pf = std::getenv("GZQR_PASSFILE");
  if(pf && *pf){ FILE* f=fopen(pf,"rb"); if(!f) throw std::runtime_error("GZQR_PASSFILE open"); std::string s; char buf[4096]; size_t n;
    while((n=fread(buf,1,sizeof(buf),f))>0) s.append(buf,n); fclose(f); while(!s.empty()&&(s.back()=='\n'||s.back()=='\r')) s.pop_back(); return s; }
  if(!::isatty(STDIN_FILENO)) throw std::runtime_error("No TTY and no GZQR_PASSFILE"); std::fprintf(stdout,"%s", label.c_str()); std::fflush(stdout);
  termios oldt,newt; tcgetattr(STDIN_FILENO,&oldt); newt=oldt; newt.c_lflag&=~ECHO; tcsetattr(STDIN_FILENO,TCSANOW,&newt);
  std::string s; std::getline(std::cin,s); tcsetattr(STDIN_FILENO,TCSANOW,&oldt); std::fprintf(stdout,"\n"); return s; }
inline std::vector<uint8_t> scrypt_kdf(const std::string& pass, const std::vector<uint8_t>& salt, const KDFParams& k){
  std::vector<uint8_t> key(32); if(1!=EVP_PBE_scrypt(pass.c_str(), pass.size(), salt.data(), salt.size(), k.N, k.r, k.p, 512ull*1024*1024, key.data(), key.size()))
    throw std::runtime_error("scrypt failed"); return key; }
inline void aes_gcm_encrypt_file(const std::string& in, const std::string& out, const std::vector<uint8_t>& key, const std::vector<uint8_t>& nonce, const std::vector<uint8_t>& aad){
  EVP_CIPHER_CTX* ctx=EVP_CIPHER_CTX_new(); if(!ctx) throw std::runtime_error("ctx"); FILE* fi=fopen(in.c_str(),"rb"); if(!fi){EVP_CIPHER_CTX_free(ctx); throw std::runtime_error("open in");}
  FILE* fo=fopen(out.c_str(),"wb"); if(!fo){fclose(fi); EVP_CIPHER_CTX_free(ctx); throw std::runtime_error("open out");}
  if(1!=EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr)) throw std::runtime_error("init");
  if(1!=EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonce.size(), nullptr)) throw std::runtime_error("ivlen");
  if(1!=EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data())) throw std::runtime_error("keyiv");
  int outl=0; if(!aad.empty()){ if(1!=EVP_EncryptUpdate(ctx,nullptr,&outl,aad.data(),aad.size())) throw std::runtime_error("aad"); }
  std::vector<uint8_t> buf(1<<20), obuf((1<<20)+16); size_t n; while((n=fread(buf.data(),1,buf.size(),fi))>0){
    if(1!=EVP_EncryptUpdate(ctx,obuf.data(),&outl,buf.data(),(int)n)) throw std::runtime_error("upd"); if(outl>0) fwrite(obuf.data(),1,outl,fo); }
  if(1!=EVP_EncryptFinal_ex(ctx,obuf.data(),&outl)) throw std::runtime_error("final"); if(outl>0) fwrite(obuf.data(),1,outl,fo);
  unsigned char tag[16]; if(1!=EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)) throw std::runtime_error("tag"); fwrite(tag,1,16,fo);
  fclose(fi); fclose(fo); EVP_CIPHER_CTX_free(ctx); }
inline std::vector<uint8_t> aes_gcm_decrypt_mem(const std::vector<uint8_t>& in, const std::vector<uint8_t>& key, const std::vector<uint8_t>& nonce, const std::vector<uint8_t>& aad){
  if(in.size()<16) throw std::runtime_error("cipher too small"); size_t csz=in.size()-16; const unsigned char* tag=in.data()+csz;
  EVP_CIPHER_CTX* ctx=EVP_CIPHER_CTX_new(); if(!ctx) throw std::runtime_error("ctx");
  if(1!=EVP_DecryptInit_ex(ctx,EVP_aes_256_gcm(),nullptr,nullptr,nullptr)) throw std::runtime_error("init");
  if(1!=EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_GCM_SET_IVLEN,nonce.size(),nullptr)) throw std::runtime_error("ivlen");
  if(1!=EVP_DecryptInit_ex(ctx,nullptr,nullptr,key.data(),nonce.data())) throw std::runtime_error("keyiv");
  int outl=0; if(!aad.empty()){ if(1!=EVP_DecryptUpdate(ctx,nullptr,&outl,aad.data(),aad.size())) throw std::runtime_error("aad"); }
  std::vector<uint8_t> out(csz+16); if(1!=EVP_DecryptUpdate(ctx,out.data(),&outl,in.data(),(int)csz)) throw std::runtime_error("upd");
  if(1!=EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_GCM_SET_TAG,16,(void*)tag)) throw std::runtime_error("settag");
  int tmplen=0; if(1!=EVP_DecryptFinal_ex(ctx,out.data()+outl,&tmplen)){EVP_CIPHER_CTX_free(ctx); throw std::runtime_error("tag mismatch"); }
  out.resize(outl+tmplen); EVP_CIPHER_CTX_free(ctx); return out; }
inline std::vector<uint8_t> read_all(const std::string&p){ FILE*f=fopen(p.c_str(),"rb"); if(!f) throw std::runtime_error("open");
  std::vector<uint8_t> v; std::vector<uint8_t>b(1<<20); size_t n; while((n=fread(b.data(),1,b.size(),f))>0) v.insert(v.end(),b.begin(),b.begin()+n); fclose(f); return v; }
inline void write_all(const std::string&p,const std::vector<uint8_t>&v){ FILE*f=fopen(p.c_str(),"wb"); if(!f) throw std::runtime_error("open out"); fwrite(v.data(),1,v.size(),f); fclose(f); }
}
