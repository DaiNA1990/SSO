using ADFS_TG.Ultility;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using sap_plugin.Dtos;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace ADFS_TG.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ADFSController : ControllerBase
    {
        private IMemoryCache _cache;
        public ADFSController(IMemoryCache memoryCache)
        {
            _cache = memoryCache;
        }
        [HttpPost]
        [Route("ADFS_GetToken")]
        public async Task<IActionResult> ADFS_GetToken([FromBody] InputDto input)
        {
            HttpClientHandler clientHandler = new HttpClientHandler();
            clientHandler.ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) => { return true; };
            using (var httpClient = new HttpClient(clientHandler))
            {
                StringContent content = new StringContent(input.data, Encoding.UTF8, "application/x-www-form-urlencoded");
                using (var response = await httpClient.PostAsync(ConfigurationManager.AppSetting["Adfs:OpenID:UrlGetToken"], content))
                {
                    string apiResponse = await response.Content.ReadAsStringAsync();
                    dynamic obj = JsonConvert.DeserializeObject<dynamic>(apiResponse);
                    return Ok(obj);
                }
            }
        }
        [HttpPost]
        [Route("ADFS_SAML_Decrypt")]
        public IActionResult ADFS_SAML_Decrypt([FromBody] InputDto input)
        {
            string SAMLResponse = "";
            string Key = input.data.Replace("SAML&code=", "");
            if (_cache.TryGetValue(Key, out SAMLResponse))
            {
                _cache.Remove(Key);
            }
            else
            {
                throw new Exception("Not Found SAML Token with Key:" + Key);
            }
            StringBuilder sbSamlResponse = new StringBuilder();
            sbSamlResponse.Append(System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(SAMLResponse)));
            XmlDocument doc = new XmlDocument();
            string strSamlResponse = sbSamlResponse.ToString();
            doc.LoadXml(sbSamlResponse.ToString());
            //Xử lý với SAML IsEncryption = true
            if (ConfigurationManager.AppSetting["Adfs:SAML:IsEncryption"] == "true")
            {
                StringBuilder sbPrivateKeyPem = new StringBuilder();
                try
                {
                    sbPrivateKeyPem.Append(System.IO.File.ReadAllText(AppContext.BaseDirectory + "/adfs_cert/PrivateKey.txt"));
                }
                catch { }
                if (sbPrivateKeyPem.Length == 0)
                {
                    throw new Exception("Not found Private Key.");
                }
                var rsa = RSA.Create();
                rsa.ImportFromPem(sbPrivateKeyPem.ToString().ToCharArray());
                var xmlNodelst = doc.GetElementsByTagName("EncryptedAssertion");
                string strEncryptedAssertion = "";
                foreach (XmlNode item in xmlNodelst)
                    strEncryptedAssertion = item.OuterXml;
                XmlDocument docEncryptedAssertion = new XmlDocument();
                docEncryptedAssertion.LoadXml(strEncryptedAssertion);
                var encryptedAssertion = new SAML2.Saml20EncryptedAssertion(rsa, docEncryptedAssertion);
                encryptedAssertion.Decrypt();
                string urlNode = ConfigurationManager.AppSetting["Adfs:SAML:UrlNameID"];
                var xmlNode = doc.SelectSingleNode(urlNode);
                string upn = "";
                if (xmlNode != null)
                {
                    upn = xmlNode.InnerText;
                    var plainTextBytes = System.Text.Encoding.UTF8.GetBytes("abcd");
                    string keyEncode = Convert.ToBase64String(plainTextBytes);
                    var plainUPNBytes = System.Text.Encoding.UTF8.GetBytes("{\"upn\":\"" + upn + "\"}");
                    string upnEncode = Convert.ToBase64String(plainUPNBytes);
                    string token = "{\"id_token\":\"" + keyEncode + "." + upnEncode + "\"}";
                    dynamic obj = JsonConvert.DeserializeObject<dynamic>(token);
                    return Ok(obj);
                }
            }    
            else
            {
                string urlNode = ConfigurationManager.AppSetting["Adfs:SAML:UrlNameID"];
                string xmlNamespaceManager = ConfigurationManager.AppSetting["Adfs:SAML:XmlNamespaceManager"];
                XmlNamespaceManager nsManager = new XmlNamespaceManager(doc.NameTable);
                try
                {
                    JArray jsonArray = JArray.Parse(xmlNamespaceManager);
                    foreach (var item in jsonArray)
                    {
                        nsManager.AddNamespace(item["prefix"].ToString(), item["uri"].ToString());
                    }
                }
                catch { }
                var xmlNode = doc.SelectSingleNode(urlNode, nsManager);
                string upn = "";
                if (xmlNode != null)
                {
                    upn = xmlNode.InnerText;
                    var plainTextBytes = System.Text.Encoding.UTF8.GetBytes("abcd");
                    string keyEncode = Convert.ToBase64String(plainTextBytes);
                    var plainUPNBytes = System.Text.Encoding.UTF8.GetBytes("{\"upn\":\"" + upn + "\"}");
                    string upnEncode = Convert.ToBase64String(plainUPNBytes);
                    string token = "{\"id_token\":\"" + keyEncode + "." + upnEncode + "\"}";
                    dynamic obj = JsonConvert.DeserializeObject<dynamic>(token);
                    return Ok(obj);
                }
            }

            throw new Exception("Not found NameID with Key:" + Key);
        }
        [HttpPost]
        [Route("ADFS_SAML_Redirect")]
        [Consumes("application/x-www-form-urlencoded")]
        public IActionResult ADFS_SAML_Redirect()
        {
            string SAMLResponse = Request.Form["SAMLResponse"];
            var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            var stringChars = new char[Convert.ToInt32(ConfigurationManager.AppSetting["Adfs:SAML:LengthCode"])];
            var random = new Random();

            for (int i = 0; i < stringChars.Length; i++)
            {
                stringChars[i] = chars[random.Next(chars.Length)];
            }

            var Key = new String(stringChars);
            string SAMLResponseCache = "";

            if (_cache.TryGetValue(Key, out SAMLResponseCache))
            {
                _cache.Remove(Key);
            }

            //// Set cache options.
            var cacheEntryOptions = new MemoryCacheEntryOptions()
                //// Keep in cache for this time, reset time if accessed.
                .SetSlidingExpiration(TimeSpan.FromSeconds(Convert.ToInt32(ConfigurationManager.AppSetting["MemoryCache:Lifetime"])));

            //// Save data in cache.
            _cache.Set(Key, SAMLResponse, cacheEntryOptions);

            string url = ConfigurationManager.AppSetting["Adfs:SAML:UrlReplingPartyTrust"];
            url = url + "?code=" + Key;
            return Redirect(url);
        }
    }
}
