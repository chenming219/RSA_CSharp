using We.Security.RSA;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using CSInteropKeys;
using we_secret;

namespace We.Security.RSA
{
    public class KeyPair
    {
        private RSACryptoServiceProvider _rsa;
        private KeyFormat _format;
        private string _private;
        private string _public;

        public KeyFormat Format
        {
            get { return this._format; }
        }

        internal KeyPair():this(1024,KeyFormat.XML)
        {
        }

        internal KeyPair(int key_len, KeyFormat format)
            : this(new RSACryptoServiceProvider(key_len), format)
        {
        }

        private KeyPair(RSACryptoServiceProvider rsa, KeyFormat format)
        {
            this._rsa = rsa;
            this._format = format;
        }

        public string PrivateKey
        {
            get
            {
                if (this._private == null)
                {
                    switch (this._format)
                    {
                        case KeyFormat.DER:
                            this._private = this._ToDERPrivateKey();
                            break;
                        case KeyFormat.ASN:
                            this._private = this._ToASNPrivateKey();                         
                            break;
                        case KeyFormat.XML:
                            this._private = this._ToXMLPrivateKey();
                            break;
                        case KeyFormat.PEM:
                            this._private = this._ToPEMPrivateKey();
                            break;
                        default:
                            this._private = this._ToXMLPrivateKey();
                            break;
                    }
                }
                return this._private;
            }
        }

        public string PublicKey
        {
            get
            {
                if (this._public == null)
                {
                    switch (this._format)
                    {
                        case KeyFormat.DER:
                            this._public = this._ToDERPublicKey();
                            break;                  
                        case KeyFormat.ASN:
                            this._public = this._ToASNPublicKey();
                            break;
                        case KeyFormat.XML:
                            this._public = this._ToXMLPublicKey();
                            break;
                        case KeyFormat.PEM:
                            this._public = this._ToPEMPublicKey();
                            break;
                        default:
                            this._public = this._ToXMLPublicKey();
                            break;
                    }
                }
                return this._public;
            }
        }

        public KeyPair ToASNKeyPair()
        {
            return new KeyPair(this._rsa, KeyFormat.ASN);
        }
        public KeyPair ToXMLKeyPair()
        {
            return new KeyPair(this._rsa, KeyFormat.XML);
        }
        public KeyPair ToPEMKeyPair()
        {
            return new KeyPair(this._rsa, KeyFormat.PEM);
        }

        private string _ToDERPublicKey()
        {
            RSAParameters publicKey = this._rsa.ExportParameters(false);
            AsnKeyBuilder.AsnMessage key = AsnKeyBuilder.PublicKeyToPKCS1(publicKey);

            return deal_string.encode_hex(key.GetBytes());
        }

        private string _ToDERPrivateKey()
        {
            RSAParameters privateKey = this._rsa.ExportParameters(true);
            AsnKeyBuilder.AsnMessage key = AsnKeyBuilder.PrivateKeyToPKCS1(privateKey);

            return deal_string.encode_hex(key.GetBytes());
        }

        private string _ToASNPublicKey()
        {
            RSAParameters publicKey = this._rsa.ExportParameters(false);
            AsnKeyBuilder.AsnMessage key = AsnKeyBuilder.PublicKeyToX509(publicKey);

            return Convert.ToBase64String(key.GetBytes());
        }
        private string _ToASNPrivateKey()
        {
            RSAParameters privateKey = this._rsa.ExportParameters(true);
            AsnKeyBuilder.AsnMessage key = AsnKeyBuilder.PrivateKeyToPKCS8(privateKey);

            return Convert.ToBase64String(key.GetBytes());
        }
        private string _ToXMLPublicKey()
        {
            return this._rsa.ToXmlString(false);
        }
        private string _ToXMLPrivateKey()
        {
            return this._rsa.ToXmlString(true);
        }
        private string _ToPEMPublicKey()
        {
            string publicKey = this._ToASNPublicKey();
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("-----BEGIN PUBLIC KEY-----");
            int i = 0;
            while (i + 64 < publicKey.Length)
            {
                sb.AppendLine(publicKey.Substring(i, 64));
                i += 64;
            }
            sb.AppendLine(publicKey.Substring(i, publicKey.Length - i));
            sb.AppendLine("-----END PUBLIC KEY-----");

            return sb.ToString();
        }
        private string _ToPEMPrivateKey()
        {
            string privateKey = this._ToASNPrivateKey();
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("-----BEGIN PRIVATE KEY-----");
            int i = 0;
            while (i + 64 < privateKey.Length)
            {
                sb.AppendLine(privateKey.Substring(i, 64));
                i += 64;
            }
            sb.AppendLine(privateKey.Substring(i, privateKey.Length - i));
            sb.AppendLine("-----END PRIVATE KEY-----");

            return sb.ToString();
        }
    }
}
