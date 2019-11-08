using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using We.Security.RSA;
using System.Security.Cryptography;

namespace we_secret
{
    public class deal_rsa
    {
        private string _pub_key;
        private string _pri_key;

        public string get_pub_key()
        {
            return this._pub_key;
        }

        public string get_pri_key()
        {
            return this._pri_key;
        }

        public void gen_rsa_key(int key_len, KeyFormat format)
        {
            if (key_len != 1024 && key_len != 2048) {
                return;
            }
            KeyPair keyPair = new KeyPair(key_len, format);

            this._pub_key = keyPair.PublicKey;
            this._pri_key = keyPair.PrivateKey;
        }

        public static string rsa_pubkey_encrypt(string pub_key, string data, KeyFormat format,int key_len = 1024)
        {
            var rsa_work = new KeyWorker(pub_key, false, format, key_len);
            var en_data = rsa_work.Encrypt(data);
            return en_data;
        }

        public static string rsa_prikey_decrypt(string pri_key, string data, KeyFormat format, int key_len = 1024)
        {
            var rsa_work = new KeyWorker(pri_key, true, format, key_len);
            var de_data = rsa_work.Decrypt(data);
            return de_data;
        }

        public static string rsa_prikey_sign(string pri_key, string en_data, KeyFormat format, int key_len = 1024)
        {
            var sign_block = deal_string.sha256(en_data).ToUpper();
            var rsa_work = new KeyWorker(pri_key, true, format, key_len);
            var sign = rsa_work.Encrypt(sign_block);
            return sign;
        }

        public static bool rsa_pubkey_verify(string pub_key, string en_data, string sign, KeyFormat format, int key_len = 1024)
        {
            var sign_block = deal_string.sha256(en_data).ToUpper();

            var rsa_work = new KeyWorker(pub_key, false, format, key_len);
            var sign_block1 = rsa_work.Decrypt(sign);

            if (sign_block.Equals(sign_block1))
            {
                return true;
            }
            else {
                return false;
            }
        }


    }
}
