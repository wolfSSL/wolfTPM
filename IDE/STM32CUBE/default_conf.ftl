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

/* ------------------------------------------------------------------------- */
/* Debugging */
/* ------------------------------------------------------------------------- */
#if defined(WOLFTPM_CONF_DEBUG) && WOLFTPM_CONF_DEBUG == 1
    #define DEBUG_WOLFTPM
#endif

#ifdef __cplusplus
}
#endif
#endif /* ${inclusion_protection}_H */

/**
  * @}
  */

/*****END OF FILE****/
