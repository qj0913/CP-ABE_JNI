#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <assert.h>
#include <glib-2.0/glib.h>
#include <pbc/pbc.h>
#include <pbc/pbc_random.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include "bswabe.h"
#include "jni.h"
#include "edu_ncepu_abe_CP_ABE.h"
#include "policy_lang.h"
#include <pbc/pbc.h>
#include <glibconfig.h>
gint
comp_string( gconstpointer a, gconstpointer b)
{
	return strcmp(a, b);
}
FILE*
fopen_read_or_die( char* file )
{
	FILE* f;

	if( !(f = fopen(file, "r")) )
		printf("%s","read error");

	return f;
}

GByteArray*
suck_file( char* file )
{
	FILE* f;
	GByteArray* a;
	struct stat s;

	a = g_byte_array_new();
	stat(file, &s);
	g_byte_array_set_size(a, s.st_size);

	f = fopen_read_or_die(file);
	fread(a->data, 1, s.st_size, f);
	fclose(f);

	return a;
}


//======    AES   ======
void init_aes(element_t k, int enc, AES_KEY* key, unsigned char* iv) {
	int key_len;
	unsigned char* key_buf;

	key_len = element_length_in_bytes(k) < 17 ? 17 : element_length_in_bytes(k);
	key_buf = (unsigned char*) malloc(key_len);
	element_to_bytes(key_buf, k);
	if (enc)
		AES_set_encrypt_key(key_buf + 1, 128, key);
	else
		AES_set_decrypt_key(key_buf + 1, 128, key);
	free(key_buf);

	memset(iv, 0, 16);
}

GByteArray* aes_128_cbc_encrypt(GByteArray* pt, element_t k) {
	AES_KEY key;
	unsigned char iv[16];
	GByteArray* ct;
	guint8 len[4];
	guint8 zero;

	init_aes(k, 1, &key, iv);

	/* TODO make less crufty */

	/* stuff in real length (big endian) before padding */
	len[0] = (pt->len & 0xff000000) >> 24;
	len[1] = (pt->len & 0xff0000) >> 16;
	len[2] = (pt->len & 0xff00) >> 8;
	len[3] = (pt->len & 0xff) >> 0;
	g_byte_array_prepend(pt, len, 4);

	/* pad out to multiple of 128 bit (16 byte) blocks */
	zero = 0;
	while (pt->len % 16)
		g_byte_array_append(pt, &zero, 1);

	ct = g_byte_array_new();
	g_byte_array_set_size(ct, pt->len);

	AES_cbc_encrypt(pt->data, ct->data, pt->len, &key, iv, AES_ENCRYPT);

	return ct;
}

GByteArray*
aes_128_cbc_decrypt(GByteArray* ct, element_t k) {
	AES_KEY key;
	unsigned char iv[16];
	GByteArray* pt;
	unsigned int len;

	init_aes(k, 0, &key, iv);

	pt = g_byte_array_new();
	g_byte_array_set_size(pt, ct->len);

	AES_cbc_encrypt(ct->data, pt->data, ct->len, &key, iv, AES_DECRYPT);

	/* TODO make less crufty */

	/* get real length */
	len = 0;
	len = len | ((pt->data[0]) << 24) | ((pt->data[1]) << 16)
			| ((pt->data[2]) << 8) | ((pt->data[3]) << 0);
	g_byte_array_remove_index(pt, 0);
	g_byte_array_remove_index(pt, 0);
	g_byte_array_remove_index(pt, 0);
	g_byte_array_remove_index(pt, 0);

	/* truncate any garbage from the padding */
	g_byte_array_set_size(pt, len);

	return pt;
}

//拼接字符串
void writeString(unsigned char* result, int len) {
	int i;
	for (i = 3; i >= 0; i--) {
		result[3 - i] = (len & 0xff << (i * 8)) >> (i * 8);
	}
}

void read_cpabe_file(unsigned char* cphtext, GByteArray** cph_buf,
		int* file_len, GByteArray** aes_buf) {
	//printf("%s\n", "Start Read!");
	int position = 0; //记录扫描到密文字符串的位置
	int i;
	int len;
	*cph_buf = g_byte_array_new();
	*aes_buf = g_byte_array_new();
	/* read real file len as 32-bit big endian int */
	*file_len = 0;
	for (i = 3; i >= 0; i--) {
		*file_len |= ((int) cphtext[position]) << (i * 8);
		position++;
	}
//	printf("Position1:%i\n", position);
//	printf("File_len:%i\n", *file_len);
	/* read aes buf */
	len = 0;
	for (i = 3; i >= 0; i--) {
		len |= ((int) cphtext[position]) << (i * 8);
		position++;
	}
//	printf("Position2:%i\n", position);
//	printf("Aes_len:%i\n", len);
	unsigned char* aes_cphtext = malloc(len * sizeof(unsigned char) + 1);
	int j = 0;
	for (i = 0; i < len; i++) {
		//aes_cphtext[j] =  cphtext[position+i];
		aes_cphtext[j] = cphtext[position];
		j++;
		position++;
	}
	//position+=len;
	//printf("Position3:%i\n", position);
	g_byte_array_append(*aes_buf, aes_cphtext, len);
	free(aes_cphtext);
	/* read cph buf */
	len = 0;
	for (i = 3; i >= 0; i--) {
		len |= ((int) cphtext[position]) << (i * 8);
		position++;
	}
//	printf("Cph_buf_len:%i\n", len);
//	printf("Position4:%i\n", position);
	unsigned char* cph_cphtext = malloc(len * sizeof(unsigned char) + 1);
	j = 0;
	for (i = 0; i < len; i++) {
////cph_cphtext[j] =  cphtext[position+i];
		cph_cphtext[j] = cphtext[position];
		j++;
		position++;
	}
	//printf("Position5:%i\n", position + i - 1);
	g_byte_array_append(*cph_buf, cph_cphtext, len);
	//free(cph_cphtext);
}
/*
 *创建公钥和主密钥
 */
JNIEXPORT jobjectArray JNICALL Java_edu_ncepu_abe_CP_1ABE_setup(JNIEnv *env,
		jclass jcls) {
	bswabe_pub_t* pub = NULL;
	bswabe_msk_t* msk = NULL;
	bswabe_setup(&pub, &msk);

	GByteArray* pubArray = bswabe_pub_serialize(pub);
	GByteArray* mskArray = bswabe_msk_serialize(msk);

////

	//unsigned char* buffer;
	jlong capacity = pubArray->len + mskArray->len;
	g_byte_array_append(pubArray, mskArray->data, mskArray->len);
	//buffer = pubArray->data;
	jobject ret_obj = (*env)->NewDirectByteBuffer(env, pubArray->data, capacity);
	g_byte_array_free(pubArray, 0);
	g_byte_array_free(mskArray, 0);

	return ret_obj;
}
/**
 *加密数据及访问策略
 */
JNIEXPORT jobject JNICALL Java_edu_ncepu_abe_CP_1ABE_encrypt(JNIEnv *env,
		jclass jcla, jbyteArray pk, jstring policy, jstring key) {
	//转化传递参数到本地
	jbyte* pubk = (*env)->GetByteArrayElements(env, pk, 0);
	const char* policyTemp = (*env)->GetStringUTFChars(env, policy, 0);
	const char* keyTemp = (*env)->GetStringUTFChars(env, key, 0);
	//开始加密过程
	bswabe_pub_t* pub;
	bswabe_cph_t* cph;
	GByteArray* cph_buf;
	GByteArray* aes_buf;
	element_t m;
	GByteArray* pub_in;
	GByteArray* key_in;
	int file_len;
	jlong capacity;
	jobject ret_obj;
	jsize len_key = (*env)->GetStringLength(env, key); //获取密钥长度
	jsize len_pk = (*env)->GetArrayLength(env, pk); //获取公钥长度

	printf("%s\n",policyTemp);
	//构造输入公钥
	pub_in = g_byte_array_new();
	g_byte_array_append(pub_in,(unsigned char*) pubk, len_pk);

	//反序列化形成属性结构
	pub = bswabe_pub_unserialize(pub_in, 1);
	//printf("%i\n",len_key);
	char* policy_real = parse_policy_lang((char*)policyTemp);
	//printf("%s\n",keyTemp);
	cph = bswabe_enc(pub, m, policy_real);
	//printf("%s\n","a3");
	if (!(cph)) {
		printf("%s\n", bswabe_error());
		return NULL ;
	}

	free(policy_real);

	//构造策略树密文
	cph_buf = bswabe_cph_serialize(cph);
	(*env)->ReleaseByteArrayElements(env, pk, pubk, 0);
	(*env)->ReleaseStringUTFChars(env, policy, policyTemp);

	///
	bswabe_cph_free(cph);
	//加密key
	key_in = g_byte_array_new();
	file_len = len_key;
	g_byte_array_append(key_in, (unsigned char*) keyTemp, len_key);
	aes_buf = aes_128_cbc_encrypt(key_in, m);
	g_byte_array_free(key_in, 0);
	(*env)->ReleaseStringUTFChars(env, key, keyTemp);
	element_clear(m);

	//printf("%s\n","a4");
	//构造返回值
	capacity = 4 * 3 + cph_buf->len + aes_buf->len ;
	unsigned char length_ch[4];
	writeString(length_ch, aes_buf->len);
//	printf("aes_buf->len %i\n", aes_buf->len);
	g_byte_array_prepend(aes_buf, length_ch, 4);
//	printf("file_len %i\n", file_len);
	writeString(length_ch, file_len);
	g_byte_array_prepend(aes_buf, length_ch, 4);
	writeString(length_ch, cph_buf->len);
	g_byte_array_append(aes_buf, length_ch, 4);
	g_byte_array_append(aes_buf, cph_buf->data, cph_buf->len);
	//buffer = aes_buf->data;
	ret_obj = (*env)->NewDirectByteBuffer(env, aes_buf->data, capacity);

	//release 资源
	g_byte_array_free(cph_buf, 0);
	g_byte_array_free(aes_buf, 0);

	return ret_obj;
}
/**
 *生成私钥
 */
JNIEXPORT jobject JNICALL Java_edu_ncepu_abe_CP_1ABE_kengen(JNIEnv *env,
		jclass jcla, jbyteArray pk, jbyteArray mk, jobjectArray attrs) {
	bswabe_pub_t* pub;
	bswabe_msk_t* msk;
	bswabe_prv_t* prv;
	unsigned char* pubkey = (unsigned char*) (*env)->GetByteArrayElements(env,
			pk, 0);
	unsigned char* mskkey = (unsigned char*) (*env)->GetByteArrayElements(env,
			mk, 0);

	int size = (*env)->GetArrayLength(env, attrs);
	int length_pub = (*env)->GetArrayLength(env, pk);
	int length_msk = (*env)->GetArrayLength(env, mk);


	GSList* alist;
	GSList* ap;
	alist = 0;
	char** attributes    = 0;
	//char** attributes = malloc((size+1) * sizeof(char*));
	int i;
	for (i = 0; i < size; i++) {
		jstring at = (jstring) (*env)->GetObjectArrayElement(env, attrs, i);
		const char* at_ch = (*env)->GetStringUTFChars(env, at, 0);
		parse_attribute(&alist, (char*)at_ch);
		//(*env)->ReleaseStringUTFChars(env,at,at_ch);
	}

	alist = g_slist_sort(alist, comp_string);
	int n = g_slist_length(alist);
	attributes = malloc((n + 1) * sizeof(char*));
	i = 0;
	for( ap = alist; ap; ap = ap->next )
		attributes[i++] = ap->data;
	attributes[i] = 0;

	//构造输入公钥
	GByteArray* pub_in = g_byte_array_new();
	//g_byte_array_set_size(pub_in, length_pub);
	g_byte_array_append(pub_in, pubkey, length_pub);
	//pub_in->data = pubkey;
	//反序列化形成属性结构
	pub = bswabe_pub_unserialize(pub_in, 1);
//		//构造输入主密钥
	GByteArray* msk_in = g_byte_array_new();
	g_byte_array_append(msk_in, mskkey, length_msk);
	//g_byte_array_set_size(msk_in, length_msk);
	//msk_in->data = mskkey;
	//反序列化形成属性结构
	msk = bswabe_msk_unserialize(pub, msk_in, 1);
	prv = bswabe_keygen(pub, msk, attributes);

	GByteArray* prvArray = bswabe_prv_serialize(prv);

	/////
//	  bswabe_msk_free(msk);
//		bswabe_pub_free(pub);
//		bswabe_prv_free(prv);
	//unsigned char* buffer;
	jlong capacity = prvArray->len;
	//buffer = prvArray->data;
	jobject ret_obj = (*env)->NewDirectByteBuffer(env, prvArray->data, capacity);
	for (i = 0; i < size + 1; i++) {
		free(attributes[i]);
	}
	free(attributes);
	g_byte_array_free(prvArray, 0);
	(*env)->ReleaseByteArrayElements(env, pk, (jbyte*) pubkey, 0);
	(*env)->ReleaseByteArrayElements(env, mk, (jbyte*) mskkey, 0);
	return ret_obj;
}
/**
 *解密数据
 */
JNIEXPORT jstring JNICALL Java_edu_ncepu_abe_CP_1ABE_decrypt(JNIEnv *env,
		jclass jcla, jbyteArray pk, jbyteArray jba_prv, jbyteArray jba_cph) {
	int length_pk = (*env)->GetArrayLength(env, pk);
	int length_jba_prv = (*env)->GetArrayLength(env, jba_prv);
	unsigned char* pubkey = (unsigned char*) (*env)->GetByteArrayElements(env,
			pk, 0);
	unsigned char* prvkey = (unsigned char*) (*env)->GetByteArrayElements(env,
			jba_prv, 0);
	unsigned char* cphtext = (unsigned char*) (*env)->GetByteArrayElements(env,
			jba_cph, 0);

	bswabe_pub_t* pub;
	bswabe_prv_t* prv;
	int file_len;
	GByteArray* aes_buf;
	GByteArray* plt;
	GByteArray* cph_buf;
	bswabe_cph_t* cph;
	element_t m;

	GByteArray* pub_in = g_byte_array_new();
	g_byte_array_append(pub_in, pubkey, length_pk);
	pub = bswabe_pub_unserialize(pub_in, 1);
	GByteArray* prv_in = g_byte_array_new();
	g_byte_array_append(prv_in, prvkey, length_jba_prv);
	prv = bswabe_prv_unserialize(pub, prv_in, 1);
	read_cpabe_file(cphtext, &cph_buf, &file_len, &aes_buf);
	cph = bswabe_cph_unserialize(pub, cph_buf, 1);

	//printf("%s\n", "开始解密规则！！");
	if (!bswabe_dec(pub, prv, cph, m)) {
		//printf("%s\n", "解密规则时出错！！");
		printf("Wrong Reason:%s", bswabe_error());
		return NULL;
	}
	bswabe_cph_free(cph);
//	bswabe_pub_free(pub);
//	bswabe_prv_free(prv);

	plt = aes_128_cbc_decrypt(aes_buf, m);
	g_byte_array_set_size(plt, file_len);
	g_byte_array_free(aes_buf, 0);

//	const jchar* buffer;
	//jlong capacity = plt->len;
	//buffer = (const char*) plt->data;
//	printf("动态链接库部分解密后长度：%i\n",plt->len);
//	printf("动态链接库部分解密后结果：%s\n",plt->data);
//	printf("动态链接库部分解密后结果buffer：%s\n",buffer);
	//jobject ret_obj = (*env)->NewDirectByteBuffer(env, buffer, capacity);
	jstring result = (*env)->NewStringUTF(env,(const char*)plt->data);
			//env,(const jchar*)plt->data,plt->len);
	g_byte_array_free(plt, 0);
	(*env)->ReleaseByteArrayElements(env, pk, (jbyte*) pubkey, 0);
	(*env)->ReleaseByteArrayElements(env, jba_prv, (jbyte*) prvkey, 0);
	(*env)->ReleaseByteArrayElements(env, jba_cph, (jbyte*) cphtext, 0);

	return result;
}

