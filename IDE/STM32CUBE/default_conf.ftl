[#ftl]
/**
  ******************************************************************************
  * File Name          : ${name}
  * Description        : This file provides code for the configuration
  *                      of the ${name} instances.
  ******************************************************************************
[@common.optinclude name=mxTmpFolder+"/license.tmp"/][#--include License text --]
  ******************************************************************************
  */
[#assign s = name]
[#assign toto = s?replace(".","_")]
[#assign toto = toto?replace("/","")]
[#assign toto = toto?replace("-","_")]
[#assign inclusion_protection = toto?upper_case]
/* Define to prevent recursive inclusion -------------------------------------*/
#ifndef __${inclusion_protection}__
#define __${inclusion_protection}__

#ifdef __cplusplus
 extern "C" {
#endif


/* Includes ------------------------------------------------------------------*/
[#if includes??]
[#list includes as include]
#include "${include}"
[/#list]
[/#if]

[#-- SWIPdatas is a list of SWIPconfigModel --]
[#list SWIPdatas as SWIP]
[#-- Global variables --]
[#if SWIP.variables??]
	[#list SWIP.variables as variable]
extern ${variable.value} ${variable.name};
	[/#list]
[/#if]

[#-- Global variables --]

[#assign instName = SWIP.ipName]
[#assign fileName = SWIP.fileName]
[#assign version = SWIP.version]

/**
	MiddleWare name : ${instName}
	MiddleWare fileName : ${fileName}
	MiddleWare version : ${version}
*/
[#if SWIP.defines??]
	[#list SWIP.defines as definition]
/*---------- [#if definition.comments??]${definition.comments}[/#if] -----------*/
#define ${definition.name} #t#t ${definition.value}
[#if definition.description??]${definition.description} [/#if]
	[/#list]
[/#if]



[/#list]

/* ------------------------------------------------------------------------- */
/* Platform */
/* ------------------------------------------------------------------------- */
#define NO_FILESYSTEM
#define NO_MAIN_DRIVER
#define WOLFTPM_EXAMPLE_HAL

/* Set smaller default timeout for embedded devices */
#define TPM_TIMEOUT_TRIES 10000

/* Example for TPM wait delay */
#if 0
    #define XTPM_WAIT() HAL_Delay(1)
#endif

/* ------------------------------------------------------------------------- */
/* Enable Features */
/* ------------------------------------------------------------------------- */
#undef WOLFTPM2_NO_WOLFCRYPT
#if defined(WOLFTPM_CONF_WOLFCRYPT) && WOLFTPM_CONF_WOLFCRYPT == 0
    #define WOLFTPM2_NO_WOLFCRYPT
#endif

#undef USE_HW_SPI_CS
#if defined(WOLFTPM_CONF_HW_SPI) && WOLFTPM_CONF_HW_SPI == 1
    #define USE_HW_SPI_CS
#endif

/* Small stack support */
#if defined(WOLFTPM_CONF_SMALL_STACK) && WOLFTPM_CONF_SMALL_STACK == 1
    #define WOLFTPM_SMALL_STACK
    #define MAX_COMMAND_SIZE    1024
    #define MAX_RESPONSE_SIZE   1350
    #define WOLFTPM2_MAX_BUFFER 1500
    #define MAX_DIGEST_BUFFER   973
#endif

/* ------------------------------------------------------------------------- */
/* Hardware */
/* ------------------------------------------------------------------------- */

/* Interface Selection SPI or I2C */
/* 0=SPI, 1=I2C */
#if defined(WOLFTPM_CONF_TRANSPORT) && WOLFTPM_CONF_TRANSPORT == 0
    /* SPI (default) */
#elif defined(WOLFTPM_CONF_TRANSPORT) && WOLFTPM_CONF_TRANSPORT == 1
    #define WOLFTPM_I2C
    #define WOLFTPM_ADV_IO
#endif

/* TPM Hardware Type (default automatic detect) */
#if 1
    #define WOLFTPM_AUTODETECT
#else
    //#define WOLFTPM_SLB9670   /* Infineon */
    //#define WOLFTPM_SLB9672   /* Infineon */
    //#define WOLFTPM_MICROCHIP /* ATTPM20 */
    //#define WOLFTPM_ST33      /* STM */
    //#define WOLFTPM_NUVOTON   /* NPCT75x */
#endif

/* Example STM32 SPI Hal Configuration */
#if 0
    /* Use PD14 for SPI1 CS */
    #define USE_SPI_CS_PORT GPIOD
    #define USE_SPI_CS_PIN  14
#endif


/* ------------------------------------------------------------------------- */
/* Debugging */
/* ------------------------------------------------------------------------- */
#if defined(WOLFTPM_CONF_DEBUG) && WOLFTPM_CONF_DEBUG == 1
    #define DEBUG_WOLFTPM
    //#define WOLFTPM_DEBUG_TIMEOUT
    //#define WOLFTPM_DEBUG_VERBOSE
    //#define WOLFTPM_DEBUG_IO
#endif

#ifdef __cplusplus
}
#endif
#endif /* ${inclusion_protection}_H */

/**
  * @}
  */

/*****END OF FILE****/
