using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
namespace JWTService.Models
{
    public class JWTContainerModel:IAuthContainerModel
    {
        #region  Public Methods
        /// <summary>
        /// Время жизни токена по умолчанию 7 дней
        /// </summary>
        /// <value></value>
        public int ExpireMinutes {get;set;} = 10080; 
        /// <summary>
        /// Секретный ключ 
        /// </summary>
        /// <value></value>
        public string SecretKey {get;set;} = "TW9zaGVFcmV6UHJpdmF0ZUtleQ==";
        /// <summary>
        /// Алгоритм шифрования по умолчанию 256-разрядный алгоритм шифрования HMAC для цифровой подписи
        /// </summary>
        /// <value></value>
        public string SecurityAlgorithm {get;set;} = SecurityAlgorithms.HmacSha256Signature;
        /// <summary>
        /// Утверждения
        /// </summary>
        /// <value></value>
        public Claim [] Claims {get;set;}
        #endregion
        public static JWTContainerModel GetJWTContainerModel(string name,string email){
            return new JWTContainerModel {
                Claims = new Claim[]
                {
                    new Claim(ClaimTypes.Name,name),
                    new Claim(ClaimTypes.Email,email)
                }
            };
        }
    }
}