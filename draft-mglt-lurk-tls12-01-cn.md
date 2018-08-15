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
LURK客户端通过rsa_master和rsa_master_with_poh请求来委托RSA密钥交换和身份验证，如[RFC5246]中所描述的。LURK服务器返回主密钥。

rsa_master请求提供必要的参数和细节来生成主密钥，同时也可以阻止异常LURK客户端重放的旧的握手消息。LURK服务器也获取了消息新限度的一些证明。

此外，rsa_master_with_poh提供了握手证明（PoH）。握手证明包括TLS客户端到LURK服务器的完成消息，所以后者可以在rsa_master模式下执行更多的检查。注意到这里，LURK服务器也会检查LURK请求是在TLS握手上下文中执行的。

而rsa_master和rsa_master_with_poh交互有着各自不同的请求，而应答消息是相同的。不同类型的动机是提供给LURK服务器的证书使用了不同的格式。rsa_master明确的提供，而rsa_master_with_poh通过握手消息来提供。

## 4.1 请求负载
rsa_master请求负载结构体如下所示：
```
enum {
   sha256_32 (0), (255)
}KeyPairIdType;

struct {
   KeyPairIdType type;
   opaque data; // length defined by the type
} KeyPairID;

enum{
   sha256 (0), (255)
} PFSAlgorithm

struct {
   KeyPairID key_id;
   PFSAlgorithm freshness_funct;
   Random client_random;        // see RFC5246 section 7.4.1.2
   Random server_random;
   EncryptedPreMasterSecret  pre_master;
               // see RFC5246 section 7.4.7.1
               // Length depends on the key.
   }
} TLS12RSAMasterRequestPayload;
```
key_id：公钥标识符。本文定义了sha256_32格式，公钥求sha256摘要，然后进行ASN.1 DER编码，最后取前32字节。RSA密钥的二进制表示详见[RFC8017](https://tools.ietf.org/html/rfc8017)。ECC密钥的二进制表示是subjectPublicKeyInfo结构，详见[RFC5480](https://tools.ietf.org/html/rfc5480)。

freshness_funct： 单项散列函数（OWHF），LURK用来实现完美向前保密。

client_random：TLS客户端产生的随机数，详见[RFC5246 7.4.1.2](https://tools.ietf.org/html/rfc5246#section-7.4.1.2)。

server_random：TLS服务端产生的随机数，详见[RFC5246  7.4.1.2](https://tools.ietf.org/html/rfc5246#section-7.4.1.2)。

EncryptedPreMasterSecret：加密的预主密钥，详见[RFC5246 7.4.7.1](https://tools.ietf.org/html/rfc5246#section-7.4.7.1)。

rsa_master_with_poh请求负载结构体如下所示：
```
struct {
   KeyPairID key_id;
   PFSAlgorithm freshness_funct;
   opaque handshake_messages<2...2^16-2>
             // see RFC5246 section 7.4.9
   Finished finished
} TLS12RSAMasterWithPoHRequestPayload;
```
handshake_messages：提供必要的握手消息来计算[RFC5246 7.4.9](https://tools.ietf.org/html/rfc5246#section-7.4.9)中描述的TLS客户端的完成消息。

finished：TLS客户端完成消息，详见[RFC5246 7.4.9](https://tools.ietf.org/html/rfc5246#section-7.4.9)。

### 4.1.1 完美向前保密
本文定义了一种机制，使用一个叫freshness_funct的函数来阻止攻击者向LURK服务器发送请求来获取老的握手的主密钥。换句话说，使用这个函数防止对过去的TLS会话的向前保密攻击，敌人使用获得的会话握手数据进行攻击。

设计使用了freshness_funct作为PFS，具有耐碰撞的哈希函数（CHRF）。使用CRHF， 意味着单向散列函数也有耐碰撞性；后者意味着找到任意输入x1和x2从而使freshness_funct(x1) = freshness_funct(x2)从计算上是不可行的。通过单项散列函数（OWHF），作为标准，哈希函数freshness_funct满足了原像抵抗性和第二原像抵抗性。也就是说，给定一个哈希值y，找到x满足freshness_funct(x)=y从计算上是不可行的，找到x2使得freshness_funct(x2) = freshness_funct(x1)从计算上也是不可行的。

对于freshness_funct函数的具体使用，记S为新鲜度，由LURK客户端随机挑选的数，TLS握手中的server_random值等于freshness_funct(S)，即server_random=freshness_funct(S)。TLS客户端和LURK服务器之间只交换了server_random。LURK客户端在请求中将S发送到KeyServer。注意到后者应该通过安全通道传输。

中间人攻击观察到TLS客户端和LURK客户端之间的TLS握手，但是看不见S，而只有server_random。freshness_funct具有的原像抵抗性保证了根据server_random获取到S。因此，这个中间人攻击不能查询到S根据过去观察到的到KeyServer的握手。而且，freshness_funct具有的抗碰撞性使得上文提到的中间人不能找到S'，使得freshness_funct(S)=freshness_funct(S')。

如第9章所述，PFS可以通过其他方式来获取（即不使用CRHF和上文提到的交互而是其他加密机元和交互）。这些可能提供更好的计算效率。有可能在LURK扩展tls12的某个未来版本中被标准化。

server_random必须遵守[RFC5246 7.4.1.2](https://tools.ietf.org/html/rfc5246)中描述的结构，在前四个字节携带gmt_unix_time。因此，TLS交换中的ServerHello.random来自于LURK交换中的server_random，如下所示：
```
gmt_unix_time = server_random[0..3];
ServerHello.random = freshness_funct( server_random + "tls12 pfs" );
ServerHello.random[0..3] = gmt_unix_time;
```
操作必须被LURK服务器和TLS服务执行，根据收到的主密钥或者来自于LURK客户端的ecdhe_params的签名。

## 4.2 应答负载
rsa_master应答负载包含了主密钥，具有如下结构：
```
struct {
   opaque master[0..47];
} TLS12RSAMasterResponsePayload;
```

## 4.3 LURK客户端行为
LURK客户端初始化一个rsa_master或者rsa_master_with_poh请求从而得到主密钥。LURK交换发生在TLS服务器端（边缘服务器）。当收到master_secret后，边缘服务器产生会话密钥并完成TLS密钥交换协议。

LURK客户端可以使用rsa_master_with_poh给LURK服务器提供LURK交换是在TLS握手上下文发生的证据。TLS握手的证据（POH）帮助了LURK服务器根据请求来审计上下文。

LURK客户端必须确保传输的server_random满足server_random = freshness_funct( S ).

## 4.4 LURK服务器行为
当收到rsa_master或rsa_master_with_poh请求后，LURK服务器处理步骤如下：
1. LURK服务器检查RSA密钥对是可用的。如果密钥对标识符不能被识别，应该返回invalid_key_id_type错误。如果指定的密钥对是不可用的，应该返回invalid_key_id错误。
2. LURK服务器检查freshness_funct。如果不支持PFS算法，应该返回invalid_prf错误。
3. LURK服务器获取rsa_master消息提供的client_random、server_random和pre_master参数，或者是rsa_master_with_poh在握手消息中提供的。
4. LURK服务器必须检查server_random的格式，尤其是检查gmt_unix_time是否正确。否则，返回invalid_tls_random错误。时间窗口的大小依据具体实现而定，应该是一个可配置的参数。LURK服务器也应该加查client_random。这需要认真考虑，因为这个检查可能阻止TLS客户端建立TLS会话。client_random是由TLS客户端生成，时钟可能和LURK服务器端不同步，或者在实现上不是根据gmt_unix_time来生成随机数。
5. LURK服务器根据server_random计算ServerHello.random，如4.1.1所述。
6. LURK服务器检查加密预主密钥的长度，如果长度不同于RSA模数的二进制表示长度，则返回invalid_payload_format错误。
7. LURK服务器解密加密的预主密钥，如[RFC5246 7.4.7.1](https://tools.ietf.org/html/rfc5246#section-7.4.7.1)所述。当检测到PKCS1.5格式错误时，或者输入的TLS版本和加密的预主密钥所暗示的TLS版本不一致时，KeyServer返回一个随机产生的主密钥。
8. LURK服务器使用LURK客户端提供的client_random，server_random产生主密钥，如[RFC5246 8.1](https://tools.ietf.org/html/rfc5246#section-8.1)所述。
9. 对于rsa_master_with_poh，LURK服务器检查完成消息，如[RFC5246 7.4.9](https://tools.ietf.org/html/rfc5246#section-7.4.9)所述。如果不匹配，则返回invalid_finished错误。
10. LURK服务器返回TLS12RSAMasterResponsePayload，包含主密钥。
11. 当发生错误时，应该将错误提供给LURK客户端，来表示错误发生的原因。当错误发生时，LURK服务器可以忽略错误或者提供更详细的错误码，如undefined_error或invalid_format。

# 5. rsa_extended_master, rss_extended_master_with_poh
rsa_extended_master交换使得LURK客户端代理RSA密钥交换和身份认证。LURK服务器返回扩展的主密钥，如[RFC7627](https://tools.ietf.org/html/rfc7627)所述。
   
## 5.1 请求负载
rsa_extended_master请求结构如下：
```
enum { sha256 (0), (255) } PRFAlgorithm

enum { null(0), sha256_128(1), sha256_256(2),
(255) }POOPRF

struct {
  KeyPairID key_id
  PFSAlgorithm freshness_funct            // see RFC5246 section 6.1
  opaque handshake_messages<2...2^16-2>
                                // see RFC7627 section 4
}TLS12ExtendedMasterRSARequestPayload;
```
rsa_extended_master_with_poh请求结构如下：
```
struct {
    KeyPairID key_id
    PFSAlgorithm freshness_funct              // see RFC5246 section 6.1
    opaque handshake_messages<2...2^16-2>
              // see RFC5246 section 7.4.9
    Finished finished
    }
}TLS12ExtendedMasterRSAWithPoHRequestPayload;
```
key_id, freshness_funct, option, handshake, finished在4.1中定义。

handshake_messages：握手消息包括产生扩展主密钥的必要信息，详见[RFC7627 第 4章](https://tools.ietf.org/html/rfc7627#section-4)。
```

## 5.2 应答负载
rsa_extended_master应答负载和4.2节描述的rsa_master应答负载具有相同的结构。

## 5.3 LURK客户端行为
LURK客户端处理详见{{sec-rsa-master-clt}。主要的区别是计算主密钥的必要元素都被包含在握手中而不是分开提供的。

## 5.4 LURK服务器行为
服务器处理如4.4节所述，除了产生扩展主密钥的过程，详见[RFC7627](https://tools.ietf.org/html/rfc7627)。

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

