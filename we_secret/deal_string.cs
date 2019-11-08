using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;

namespace we_secret
{
    public class deal_string
    {
        public static string encode_base64(Byte[] in_byte){
            string ret_string = Convert.ToBase64String(in_byte);
            return ret_string;
        }

        public static Byte[] decode_base64(string in_base64)
        {
            byte[] ret_bytes = Convert.FromBase64String(in_base64);
            return ret_bytes;
        }

        public static string encode_hex(Byte[] in_byte)
        {
            StringBuilder hex = new StringBuilder(in_byte.Length * 2);
            foreach (byte b in in_byte)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString().ToUpper();
        }

        public static byte[] decode_hex(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }

        public static string sha256(string data)
        {
           byte[] bytes = Encoding.UTF8.GetBytes(data);
           byte[] hash = SHA256Managed.Create().ComputeHash(bytes);
           StringBuilder builder = new StringBuilder();
           for (int i = 0; i < hash.Length; i++)
           {
                  builder.Append(hash[i].ToString("X2"));
           }
           return builder.ToString();
        }
    }
}
