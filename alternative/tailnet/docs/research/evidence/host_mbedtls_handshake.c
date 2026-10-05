#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/platform.h"
#include "mbedtls/error.h"
#define MAXA 262144
static void*ptrs[MAXA];static size_t szs[MAXA];static int np=0;static size_t live=0,peak=0;static size_t snap[MAXA];static int nsnap=0; static size_t hdr=16;
typedef struct{size_t n;}H;
static void *mycalloc(size_t a,size_t b){size_t n=a*b;H*h=calloc(1,n+hdr);h->n=n;live+=n;ptrs[np]=(char*)h+hdr;szs[np]=n;np++;if(live>peak){peak=live;nsnap=0;for(int i=0;i<np;i++)if(ptrs[i])snap[nsnap++]=szs[i];}return (char*)h+hdr;}
static void myfree(void*p){if(!p)return;H*h=(H*)((char*)p-hdr);live-=h->n;for(int i=0;i<np;i++)if(ptrs[i]==p){ptrs[i]=0;break;}free(h);}
static int fd; static int rx_total=0;
static unsigned char hbuf[5]; static int hgot=0; static int body_left=0;
static int rx(void*c,unsigned char*b,size_t l){ssize_t n=recv(fd,b,l,0);if(n<=0)return MBEDTLS_ERR_SSL_CONN_EOF;
  /* parse record headers in the stream */
  for(ssize_t i=0;i<n;i++){ if(body_left>0){body_left--;continue;} hbuf[hgot++]=b[i]; if(hgot==5){int len=(hbuf[3]<<8)|hbuf[4];printf("  [rec in] type=%d len=%d (total_rx_so_far=%d)\n",hbuf[0],len,rx_total);body_left=len;hgot=0;} }
  rx_total+=n; return n;}
static int tx(void*c,const unsigned char*b,size_t l){ssize_t n=send(fd,b,l,0);return n<=0?MBEDTLS_ERR_SSL_CONN_EOF:n;}
static int cmp(const void*a,const void*b){return *(size_t*)b>*(size_t*)a?1:-1;}
int main(int argc,char**argv){
 mbedtls_platform_set_calloc_free(mycalloc,myfree);
 const char*host=argv[1];
 struct addrinfo hints={0},*res;hints.ai_socktype=SOCK_STREAM;getaddrinfo(host,"443",&hints,&res);
 fd=socket(res->ai_family,SOCK_STREAM,0);connect(fd,res->ai_addr,res->ai_addrlen);
 static mbedtls_ssl_context ssl;static mbedtls_ssl_config conf;static mbedtls_entropy_context ent;static mbedtls_ctr_drbg_context drbg;
 mbedtls_ssl_init(&ssl);mbedtls_ssl_config_init(&conf);mbedtls_entropy_init(&ent);mbedtls_ctr_drbg_init(&drbg);
 mbedtls_ctr_drbg_seed(&drbg,mbedtls_entropy_func,&ent,NULL,0);
 mbedtls_ssl_config_defaults(&conf,MBEDTLS_SSL_IS_CLIENT,MBEDTLS_SSL_TRANSPORT_STREAM,MBEDTLS_SSL_PRESET_DEFAULT);
 mbedtls_ssl_conf_authmode(&conf,MBEDTLS_SSL_VERIFY_NONE);mbedtls_ssl_conf_rng(&conf,mbedtls_ctr_drbg_random,&drbg);
 size_t base=live;
 int r=mbedtls_ssl_setup(&ssl,&conf);printf("setup=%d live_after_setup=%zu (in+out bufs incl.)\n",r,live-base);
 mbedtls_ssl_set_hostname(&ssl,host);mbedtls_ssl_set_bio(&ssl,NULL,tx,rx,NULL);
 size_t before=live; peak=live; nsnap=0;
 while((r=mbedtls_ssl_handshake(&ssl))!=0){if(r==MBEDTLS_ERR_SSL_WANT_READ||r==MBEDTLS_ERR_SSL_WANT_WRITE)continue;char e[100];mbedtls_strerror(r,e,100);printf("hs fail %s\n",e);return 1;}
 {qsort(snap,nsnap,sizeof(size_t),cmp);printf("allocs live at peak (%d): ",nsnap);for(int i=0;i<nsnap&&i<14;i++)printf("%zu ",snap[i]);printf("\n");}
 printf("suite=%s ver=%s\n",mbedtls_ssl_get_ciphersuite(&ssl),mbedtls_ssl_get_version(&ssl));
 printf("handshake: peak_live=%zu (incl. 20.7KB static in/out bufs); peak_excl_bufs=%zu; live_after=%zu; live_after_excl_bufs=%zu; rx_bytes=%d\n",peak,peak-(16717+4429),live,live-(16717+4429),rx_total);
 const char*q="GET /derp HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: DERP\r\n\r\n";mbedtls_ssl_write(&ssl,(const unsigned char*)q,strlen(q));
 unsigned char buf[2048];int n=mbedtls_ssl_read(&ssl,buf,sizeof buf);printf("read %d\n",n);
 n=mbedtls_ssl_read(&ssl,buf,sizeof buf);printf("read %d\n",n);
 return 0;}
