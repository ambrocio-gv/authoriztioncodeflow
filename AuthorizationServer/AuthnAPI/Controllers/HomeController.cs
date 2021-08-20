using AuthnAPI.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;


using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;

namespace AuthnAPI.Controllers
{
    public class HomeController : Controller
    {


        [Authorize]
        public async Task<IActionResult> Secret()
        {
            //var serverResponse = await AccessTokenRefreshWrapper(
            //    () => SecuredGetRequest("https://localhost:44358/secret/index"));

            //var apiResponse = await AccessTokenRefreshWrapper(
            //    () => SecuredGetRequest("https://localhost:44303/secret/index"));


            var token = HttpContext.GetTokenAsync("access_token");



            return View();
        }





        //login
        public async Task<IActionResult> Index()
        {
            //try
            //{
            //    var token = await _authnService.GetToken();
            //}
            //catch(Exception ex)
            //{
            //    Debug.Write(ex);
            //}

            return View();
        }

        //register
        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
