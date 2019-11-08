using We.Security.RSA;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using CSInteropKeys;
using we_secret;
using System.IO;

namespace We.Security.RSA
{
    public class KeyWorker
    {
        /// <summary>
        /// xml key
        /// </summary>
        private string _key;
        private KeyFormat _format;
        private RSACryptoServiceProvider _provider;
        private bool _isPrivate;
        private int _key_len;
        public KeyWorker(string key, bool isPrivate, KeyFormat format = KeyFormat.XML, int key_len = 1024)
        {
            this._key = key;
            this._format = format;
            this._key_len = key_len;
            this._isPrivate = isPrivate;
        }

        public string Encrypt(string data)
        {
            this._MakesureProvider();

            //原生.NET不提供私钥加密，公钥解密的方法，所以只能自行实现，但性能不知道如何。
            byte[] bytes = this._isPrivate ? this._EncryptByPriKey(UTF8Encoding.UTF8.GetBytes(data), this._provider) : this._EncryptByPubKey(UTF8Encoding.UTF8.GetBytes(data), this._provider);
            // byte[] bytes = this._provider.Encrypt(UTF8Encoding.UTF8.GetBytes(data), false);
            return deal_string.encode_hex(bytes);
        }

        public string Decrypt(string data)
        {
            this._MakesureProvider();

            //原生.NET不提供私钥加密，公钥解密的方法，所以只能自行实现，但性能不知道如何。
            byte[] bytes = this._isPrivate ? this._DecryptByPriKey(deal_string.decode_hex(data), this._provider) : this._DecryptByPubKey(deal_string.decode_hex(data), this._provider);
            return UTF8Encoding.UTF8.GetString(bytes);
        }

        private void _MakesureProvider()
        {
            if (this._provider != null) return;

            _isPrivate = this._isPrivate;

            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(this._key_len);

            switch (this._format)
            {
                case KeyFormat.DER:
                    {
                        var b_key = deal_string.decode_hex(this._key);
                        AsnKeyParser keyParser = new AsnKeyParser(b_key);
                        RSAParameters key = _isPrivate ? keyParser.ParseRSAPrivateKeyPKCS1() : keyParser.ParseRSAPublicKeyPKCS1();
                        rsa.ImportParameters(key);

                        break;
                    }
                case KeyFormat.PEM:
                    {
                        this._key = this._key.Replace("-----BEGIN PUBLIC KEY-----", "").Replace("-----END PUBLIC KEY-----", "")
                                              .Replace("-----BEGIN PRIVATE KEY-----", "").Replace("-----END PRIVATE KEY-----", "")
                                              .Replace("\r\n", "");
                        goto case KeyFormat.ASN;
                    }
                case KeyFormat.ASN:
                    {
                        var b_key = deal_string.decode_base64(this._key);
                        AsnKeyParser keyParser = new AsnKeyParser(b_key);
                        RSAParameters key = _isPrivate ? keyParser.ParseRSAPrivateKey() : keyParser.ParseRSAPublicKey();
                        rsa.ImportParameters(key);

                        break;
                    }
                case KeyFormat.XML:
                default:
                    //_isPrivate = this._key.IndexOf("<D>") > -1;
                    rsa.FromXmlString(this._key);
                    break;
            }

            this._provider = rsa;
        }

        public byte[] _EncryptByPubKey(byte[] inputBytes, RSACryptoServiceProvider key)
        {
            int bufferSize = (key.KeySize / 8) - 11;//单块最大长度

            var buffer = new byte[bufferSize];

            using (MemoryStream inputStream = new MemoryStream(inputBytes),
                 outputStream = new MemoryStream())
            {
                while (true)
                {
                    int readSize = inputStream.Read(buffer, 0, bufferSize);
                    if (readSize <= 0)
                    {
                        break;
                    }
                    var temp = new byte[readSize];
                    Array.Copy(buffer, 0, temp, 0, readSize);
                    var encryptedBytes = key.Encrypt(temp, false);
                    outputStream.Write(encryptedBytes, 0, encryptedBytes.Length);
                }
                return outputStream.ToArray();
            }
        }

        public byte[] _DecryptByPriKey(byte[] inputBytes, RSACryptoServiceProvider key)
        {
            int bufferSize = key.KeySize / 8;
            var buffer = new byte[bufferSize];
            using (MemoryStream inputStream = new MemoryStream(inputBytes),
                 outputStream = new MemoryStream())
            {
                while (true)
                {
                    int readSize = inputStream.Read(buffer, 0, bufferSize);
                    if (readSize <= 0)
                    {
                        break;
                    }

                    var temp = new byte[readSize];
                    Array.Copy(buffer, 0, temp, 0, readSize);
                    var rawBytes = key.Decrypt(temp, false);
                    outputStream.Write(rawBytes, 0, rawBytes.Length);
                }
                return outputStream.ToArray();
            }

        }


        #region 自行实现的RSA PKCS1填充方式的算法

        //填充
        private byte[] _AddPKCS1Padding(byte[] oText, int blockLen)
        {
            byte[] result = new byte[blockLen];
            result[0] = 0x00;
            result[1] = 0x01;
            int padLen = blockLen - 3 - oText.Length;
            for (int i = 0; i < padLen; i++)
            {
                result[i + 2] = 0xff;
            }
            result[padLen + 2] = 0x00;
            int j = 0;
            for (int i = padLen + 3; i < blockLen; i++)
            {
                result[i] = oText[j++];
            }
            return result;
        }

        //私钥加密
        private byte[] priEncrypt(byte[] block, RSACryptoServiceProvider key)
        {
            RSAParameters param = key.ExportParameters(true);
            BigInteger d = new BigInteger(param.D);
            BigInteger n = new BigInteger(param.Modulus);
            BigInteger biText = new BigInteger(block);
            BigInteger biEnText = biText.modPow(d, n);
            return biEnText.getBytes();
        }

        private byte[] _EncryptByPriKey(byte[] oText, RSACryptoServiceProvider key)
        {
            //获得明文字节数组
            //byte[] oText = System.Text.Encoding.UTF8.GetBytes(src);
            //填充
            oText = this._AddPKCS1Padding(oText, 128);
            //加密
            byte[] result = this.priEncrypt(oText, key);
            return result;
        }

        //公钥解密
        public byte[] _DecryptByPubKey(byte[] enc, RSACryptoServiceProvider key)
        {

            byte[] result = new byte[enc.Length];
            int k = 0;
            int blockLen = 128;
            int i = 0;
            do
            {
                //String temp = enc.Substring(i, blockLen);
                int length = (enc.Length - blockLen * i) > blockLen ? blockLen : (enc.Length - blockLen * i);
                byte[] oText = new byte[length];
                Array.Copy(enc, i * blockLen, oText, 0, length);

                //解密
                byte[] dec = pubDecrypt(oText, key);
                //if (dec.Length < blockLen)
                //{
                //    int offset = blockLen - dec.Length;
                //    Byte[] fitBytes = new byte[blockLen];
                //    for (int j = 0; j < offset; j++)
                //    {
                //        fitBytes[j] = 0x00;
                //    }
                //    Array.Copy(dec, 0, fitBytes, offset, dec.Length);
                //    dec = fitBytes;
                //}
                //去除填充
                dec = remove_PKCS1_padding(dec);
                Array.Copy(dec, 0, result, k, dec.Length);
                k += dec.Length;
                //result += System.Text.Encoding.Default.GetString(dec);

                i++;
            } while (i * blockLen < enc.Length);

            byte[] data = new byte[k];
            Array.Copy(result, 0, data, 0, k);
            return data;
        }

        //公钥解密
        private byte[] pubDecrypt(byte[] block, RSACryptoServiceProvider key)
        {
            RSAParameters param = key.ExportParameters(false);
            BigInteger e = new BigInteger(param.Exponent);
            BigInteger n = new BigInteger(param.Modulus);
            BigInteger biText = new BigInteger(block);
            BigInteger biEnText = biText.modPow(e, n);
            return biEnText.getBytes();
        }

        //去除填充
        private byte[] remove_PKCS1_padding(byte[] oText)
        {
            int i = 2;
            byte b = (byte)(oText[i] & 0xff);
            while (b != 0)
            {
                i++;
                b = (byte)(oText[i] & 0xff);
            }
            i++;

            byte[] result = new byte[oText.Length - i];
            int j = 0;
            while (i < oText.Length)
            {
                result[j++] = oText[i++];
            }
            return result;
        }

        #endregion
    }
}
