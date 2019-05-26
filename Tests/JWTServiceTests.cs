using System.Collections.Generic;
using System.Security.Claims;
using System.Linq;
using NUnit.Framework;
using JWTService.Models;
using JWTService.Manager;

namespace Tests
{
    public class JWTServiceTests
    {
        IAuthContainerModel model;
        IAuthService service;
        string token;
        [SetUp]
        public void Setup()
        {
            model = JWTContainerModel.GetJWTContainerModel("Dmitry Ershov","dmitryershov0@gmail.com");
            service = new JWTAuthService(model.SecretKey);

        }

        [Test]
        public void GenerateToken_Test()
        {
            token = service.GenerateToken(model);
            Assert.IsNotNull(token);
        }
        [Test]
        public void ValidationToken_Test()
        {
            var result = service.IsTokenValid(token);
            Assert.IsTrue(result);
        }
        [Test]
        public void GetTokensClaims_Test()
        {
            var result = service.GetTokenClaims(token).ToList();
            var name = result.FirstOrDefault(x=>x.Type.Equals(ClaimTypes.Name)).Value;
            Assert.AreEqual("Dmitry Ershov",name);
            var email = result.FirstOrDefault(y=>y.Type.Equals(ClaimTypes.Email)).Value;
            Assert.AreEqual("dmitryershov0@gmail.com",email);
        }
    }
}