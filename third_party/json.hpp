#pragma once
#include <string>
#include <map>
#include <vector>
#include <variant>
#include <stdexcept>
#include <sstream>
#include <cctype>
namespace mini_json {
  struct value {
    using var = std::variant<std::nullptr_t, bool, double, std::string,
                             std::map<std::string, value>, std::vector<value>>;
    var v; value():v(nullptr){} value(const char*s):v(std::string(s)){} value(const std::string&s):v(s){}
    value(double d):v(d){} value(bool b):v(b){} value(const std::map<std::string,value>&o):v(o){}
    value(const std::vector<value>&a):v(a){}
    bool is_obj()const{return std::holds_alternative<std::map<std::string,value>>(v);}
    bool is_arr()const{return std::holds_alternative<std::vector<value>>(v);}
    bool is_str()const{return std::holds_alternative<std::string>(v);}
    bool is_num()const{return std::holds_alternative<double>(v);}
    bool is_bool()const{return std::holds_alternative<bool>(v);}
    std::map<std::string,value>& obj(){return std::get<std::map<std::string,value>>(v);}
    const std::map<std::string,value>& obj()const{return std::get<std::map<std::string,value>>(v);}
    std::vector<value>& arr(){return std::get<std::vector<value>>(v);}
    const std::vector<value>& arr()const{return std::get<std::vector<value>>(v);}
    std::string& str(){return std::get<std::string>(v);}
    const std::string& str()const{return std::get<std::string>(v);}
    double num()const{return std::get<double>(v);} bool boolean()const{return std::get<bool>(v);}
    value& operator[](const std::string&k){return obj()[k];}
    const value& operator[](const std::string&k)const{return obj().at(k);}
    bool contains(const std::string&k)const{return is_obj()&&obj().count(k);}
    template<typename T> T get() const;
    std::string dump()const{ std::ostringstream o; dump_into(o); return o.str(); }
    static value parse(const std::string&s){ size_t i=0; return parse_any(s,i); }
  private:
    static void skipws(const std::string&s,size_t&i){ while(i<s.size()&&std::isspace((unsigned char)s[i])) ++i; }
    static value parse_any(const std::string&s,size_t&i){
      skipws(s,i); if(i>=s.size()) throw std::runtime_error("json eof");
      if(s[i]=='{') return parse_obj(s,i); if(s[i]=='[') return parse_arr(s,i);
      if(s[i]=='"') return parse_str(s,i);
      if(std::isdigit((unsigned char)s[i])||s[i]=='-') return parse_num(s,i);
      if(s.compare(i,4,"true")==0){i+=4;return value(true);} if(s.compare(i,5,"false")==0){i+=5;return value(false);}
      if(s.compare(i,4,"null")==0){i+=4;return value();} throw std::runtime_error("json parse");
    }
    static value parse_obj(const std::string&s,size_t&i){
      std::map<std::string,value> o; ++i; skipws(s,i); if(s[i]=='}'){++i;return value(o);}
      while(true){ auto k=parse_str(s,i).str(); skipws(s,i); if(s[i++]!=':') throw std::runtime_error(":");
        auto v=parse_any(s,i); o.emplace(k,std::move(v)); skipws(s,i);
        if(s[i]=='}'){++i;break;} if(s[i++]!=',') throw std::runtime_error(",");
      } return value(o);
    }
    static value parse_arr(const std::string&s,size_t&i){
      std::vector<value>a; ++i; skipws(s,i); if(s[i]==']'){++i;return value(a);}
      while(true){ a.push_back(parse_any(s,i)); skipws(s,i);
        if(s[i]==']'){++i;break;} if(s[i++]!=',') throw std::runtime_error(",");
      } return value(a);
    }
    static value parse_str(const std::string&s,size_t&i){
      if(s[i]!='"') throw std::runtime_error("\""); ++i; std::string r;
      while(i<s.size()&&s[i]!='"'){ if(s[i]=='\\'){ ++i; if(i<s.size()) r.push_back(s[i++]); } else r.push_back(s[i++]); }
      if(i>=s.size()||s[i]!='"') throw std::runtime_error("unterminated string"); ++i; return value(r);
    }
    static value parse_num(const std::string&s,size_t&i){
      size_t j=i; while(j<s.size()&&(std::isdigit((unsigned char)s[j])||s[j]=='-'||s[j]=='+'||s[j]=='.'||s[j]=='e'||s[j]=='E')) ++j;
      double d=std::stod(s.substr(i,j-i)); i=j; return value(d);
    }
    void dump_into(std::ostringstream&o)const{
      if(std::holds_alternative<std::nullptr_t>(v)){o<<"null";return;}
      if(is_bool()){o<<(boolean()?"true":"false");return;}
      if(is_num()){o<<num();return;}
      if(is_str()){o<<'"';for(char c:str()){ if(c=='"'||c=='\\')o<<'\\'<<c; else o<<c;}o<<'"';return;}
      if(is_arr()){o<<'[';bool f=1;for(auto&e:arr()){if(!f)o<<',';f=0;e.dump_into(o);}o<<']';return;}
      if(is_obj()){o<<'{';bool f=1;for(auto&kv:obj()){if(!f)o<<',';f=0;o<<'"'<<kv.first<<'"'<<':';kv.second.dump_into(o);}o<<'}';return;}
    }
  };
  template<> inline std::string value::get<std::string>()const{return str();}
  template<> inline int         value::get<int>()const{return (int)num();}
  template<> inline double      value::get<double>()const{return num();}
  template<> inline bool        value::get<bool>()const{return boolean();}
}
