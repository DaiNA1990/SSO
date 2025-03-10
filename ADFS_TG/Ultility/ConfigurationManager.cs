﻿using Microsoft.Extensions.Configuration;
using System;
using System.IO;


namespace ADFS_TG.Ultility
{
    static class ConfigurationManager
    {
        public static IConfiguration AppSetting { get; }
        static ConfigurationManager()
        {
            AppSetting = new ConfigurationBuilder()
                    .SetBasePath(Directory.GetCurrentDirectory())
                    .AddJsonFile("appsettings.json" +
                    "")
                    .Build();
        }
    }
}
