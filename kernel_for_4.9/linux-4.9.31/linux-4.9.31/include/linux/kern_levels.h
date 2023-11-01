#ifndef __KERN_LEVELS_H__
#define __KERN_LEVELS_H__

#define KERN_SOH	"\001"		/* ASCII Start Of Header */
#define KERN_SOH_ASCII	'\001'
//如果这句话被打印出来了，说明内核根本就启动不起来，系统根本没法运行
#define KERN_EMERG	KERN_SOH "0"	/* system is unusable */
//这句话表示出现了一个禁忌情况，你必须要处理，你如果不处理可能内核就立马死掉了
#define KERN_ALERT	KERN_SOH "1"	/* action must be taken immediately */
//这个表示死不了人，但是非常危险  	相当于站在悬崖边上了
#define KERN_CRIT	KERN_SOH "2"	/* critical conditions */
//这个表示出现一个错误
#define KERN_ERR	KERN_SOH "3"	/* error conditions */
//这个表示出现警告
#define KERN_WARNING	KERN_SOH "4"	/* warning conditions */
//这个表示就是用来公告信息的
#define KERN_NOTICE	KERN_SOH "5"	/* normal but significant condition */
//这个也是发布消息，只是发布的级别比KERN_NOTICE还要低
#define KERN_INFO	KERN_SOH "6"	/* informational */
//这个就是用来调试的
#define KERN_DEBUG	KERN_SOH "7"	/* debug-level messages */

#define KERN_DEFAULT	KERN_SOH "d"	/* the default kernel loglevel */

/*
 * Annotation for a "continued" line of log printout (only done after a
 * line that had no enclosing \n). Only to be used by core/arch code
 * during early bootup (a continued line is not SMP-safe otherwise).
 */
#define KERN_CONT	KERN_SOH "c"

/* integer equivalents of KERN_<LEVEL> */
#define LOGLEVEL_SCHED		-2	/* Deferred messages from sched code
					 * are set to this special level */
#define LOGLEVEL_DEFAULT	-1	/* default (or last) loglevel */
#define LOGLEVEL_EMERG		0	/* system is unusable */
#define LOGLEVEL_ALERT		1	/* action must be taken immediately */
#define LOGLEVEL_CRIT		2	/* critical conditions */
#define LOGLEVEL_ERR		3	/* error conditions */
#define LOGLEVEL_WARNING	4	/* warning conditions */
#define LOGLEVEL_NOTICE		5	/* normal but significant condition */
#define LOGLEVEL_INFO		6	/* informational */
#define LOGLEVEL_DEBUG		7	/* debug-level messages */

#endif
