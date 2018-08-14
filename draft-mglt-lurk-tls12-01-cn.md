# 1. 介绍
本文描述了TLS 1.2协议的LURK扩展，即在TLS 1.2和DTLS 1.2的上下文中，LURK服务器可以实现加密服务。

更具体的说，LURK服务器将负责执行与TLS服务器的私钥相关的加密操作，而终止TLS会话的其他方面是位于同一管理域或不同管理域中的其他服务来处理。大部分的加密操作是和TLS身份验证相关的，本文限制加密操作的身份验证方法为：RSA、ECDHE_RSA和ECDHE_ECDSA。

有关TLS上下文中预见的一些用例的详细描述可以在[I-D.mglt-lurk-tls-use-cases](https://tools.ietf.org/html/draft-mglt-lurk-tls12-01#ref-I-D.mglt-lurk-tls-use-cases)中找到。

HTTPS委托一直成为CDNI（Content Delivery Networks Interconnection）工作组主要的关注点，几种机制已经将负载从上游实体委托给下游实体。实体可以根据上下文的不同而具有不同的特点。通常委托包括内容所有者，CDN提供商，域名所有者。 [I-D.fieau-cdni-https-delegation]关于CDN互联的各种机制给出了详细的比较，本节的剩余部分将以高层次的视角来讨论一下这些机制。

STAR [I-D.ietf-acme-star](https://tools.ietf.org/html/draft-mglt-lurk-tls12-01#ref-I-D.ietf-acme-star),
[I-D.sheffer-acme-star-request](https://tools.ietf.org/html/draft-mglt-lurk-tls12-01#ref-I-D.sheffer-acme-star-request)描述了一种方法，域名所有者或者内容所有者编排CA和CDN之间的刷新过程（终止TLS回话）。CDN使用[I-D.ietf-acme-acme](https://tools.ietf.org/html/draft-mglt-lurk-tls12-01#ref-I-D.ietf-acme-acme)定期的自动刷新证书，允许使用短期证书。

委托的凭证 [I-D.rescorla-tls-subcerts](https://tools.ietf.org/html/draft-mglt-lurk-tls12-01#ref-I-D.rescorla-tls-subcerts)通过使用一个证书，让服务器来产生“委托的凭证”。

STAR和“委托的凭证”都需要CA做一些改变，适用委托凭证的新的证书类型，以及对于STAR的被委托方和委托方实体的新接口。在两种情况下，TLS客户端验证被委托给实体。而对于STAR，TLS客户端不需要改变，“委托凭证”方案需要。在两种情况下，委托被限制在一定时间内（7天），也限制了对被盗密钥和假冒服务器的使用。这种委托提供了架构上的高可扩展性，并且防止了在建立TLS回话时产生额外的延迟。

LURK架构和LURK扩展tls12，不会通过委派整个TLS终止来继续进行HTTPS委派的委派。相反，TLS终止被划分成子服务，例如网络部分和加密操作部分。跟网络部分相关的微服务是被委派的，和加密操作相关的微服务是不可以被委派的。结果，LURK架构专注于保护加密材料，组织加密材料的泄漏，例如通过避免托管加密材料的节点暴露在互联网上。此外，LURK提供了立刻终止可疑节点的代理。另一方面，LURK扩展tls12引入了一些延迟，而且不像STAR和委托凭证方案那样可扩展。

LURK扩展tls12可以被看成是STAR和委托凭证方案的补充。LURK扩展tls12是一个后端的解决方案，不需要TLS客户端和CA做任何修改。这也做的目的也是为了保护加密材料。

LURK也可以部署在一个管理域中，从而可以更好的控制TLS服务器的部署。

# 2. 术语和缩略词
本文复用了[I-D.mglt-lurk-lurk](https://tools.ietf.org/html/draft-mglt-lurk-tls12-01#ref-I-D.mglt-lurk-lurk)中定义的术语。

# 3. LURK首部
LURK TLS1.2是LURK扩展，引入了新的名称“tls12”。本文将扩展定义为“tls12”，版本号为1。LURK扩展扩充了在[I-D.mglt-lurk-lurk](https://tools.ietf.org/html/draft-mglt-lurk-tls12-01#ref-I-D.mglt-lurk-lurk)中定义的LURKHeader结构。如下所示：
```
enum {
   tls12 (1), (255)
} Designation;

enum {
  capabilities (0), ping (1), rsa_master (2),
  rsa_extended_master (3), ecdhe (4), (255)
}TLS12Type;


enum {
   // generic values reserved or aligned with the
   // LURK Protocol
   request (0), success (1), undefined_error (2),
   invalid_payload_format (3),

   // code points for rsa authentication
   invalid_key_id_type (4), invalid_key_id (5),
   invalid_tls_random (6), invalid_prf (7),
   invalid_encrypted_premaster (8), invalid_finished (9)

   //code points for ecdhe authentication
   invalid_ec_type (10), invalid_ec_curve (11),
   invalid_poo_prf (12), invalid_poo (13), (255)
}TLS12Status

struct {
    Designation designation = "tls12";
    int8 version = 1;
} Extension;

struct {
   Extension extension;
   select( Extension ){
       case ("tls12", 1):
           TLS12Type;
   } type;
   select( Extension ){
       case ("tls12", 1):
           TLS12Status;
   } status;
   uint64 id;
   unint32 length;
} LURKHeader;
```

# 4. rsa_master, rsa_master_with_poh
## 4.1 请求负载
### 4.1.1 完美向前保密
## 4.2 应答负载
## 4.3 LURK客户端行为
## 4.4 LURK服务器行为
# 5. rsa_extended_master, rss_extended_master_with_poh
## 5.1 请求负载
## 5.2 应答负载
## 5.3 LURK客户端行为
## 5.4 LURK服务器行为
# 6. ecdhe
## 6.1 请求负载
## 6.2 应答负载
## 6.3 LURK客户端行为
## 6.4 LURK服务器行为
# 7. 能力
## 7.1 请求负载
## 7.2 应答负载
## 7.3 LURK客户端行为
## 7.4 LURK服务器行为
# 8. ping
## 8.1 请求负载
## 8.2 应答负载
## 8.3 LURK客户端行为
## 8.4 LURK服务器行为
# 9. 安全考虑
## 9.1 RSA
## 9.2 ECDHE
## 9.3 Perfect Foward Secrecy
# 10. IANA考虑
# 11. 致谢
# 12. 附录
# 13. 参考文献

