using AspMvcAuth.Data;
using AspMvcAuth.Models;
using AspMvcAuth.Repositories;
using Microsoft.AspNet.Identity;
using Microsoft.Owin.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Web;
using System.Web.Mvc;

namespace AspMvcAuth.Controllers
{
    public class AccountController : Controller
    {
        private readonly IAuthenticationManager _auth;
        private readonly IAccount _accountServices;

        public AccountController(IAuthenticationManager auth, IAccount accountServices)
        {
            this._auth = auth;
            this._accountServices = accountServices;
        }

        // GET: Account
        [AllowAnonymous]
        public ActionResult Login(string returnUrl)
        {
            ViewBag.ReturnUrl = returnUrl;
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult Login(LoginViewModel model)
        {
            if (!ModelState.IsValid)
                return View();

			// pmcao begins
			Session["SVAuth_UserID"] = "pmcao";


			if (Session["SVAuth_UserID"] != "")
			{
				var username = Session["SVAuth_UserID"];
				var identity = new ClaimsIdentity(new[] { new Claim(ClaimTypes.Name, username.ToString()), }, DefaultAuthenticationTypes.ApplicationCookie);
				// pmcao ends


				this._auth.SignIn(new AuthenticationProperties
                {
                    IsPersistent = model.RememberMe
                }, identity);
                
                return RedirectToAction("Index", "Home");
            }
            else
            {
                ModelState.AddModelError("", "Invalid login attempt.");
                return View(model);
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult LogOff()
        {
            this._auth.SignOut();
            return RedirectToAction("Login", "Account");
        }

    }
}