/*
 *
 *	V 4 L 2   D R I V E R   H E L P E R   A P I
 *
 * Moved from videodev2.h
 *
 *	Some commonly needed functions for drivers (v4l2-common.o module)
 */
#ifndef _V4L2_IOCTL_H
#define _V4L2_IOCTL_H

#include <linux/poll.h>
#include <linux/fs.h>
#include <linux/mutex.h>
#include <linux/compiler.h> /* need __user */
#include <linux/videodev2.h>

struct v4l2_fh;

/**
 * struct v4l2_ioctl_ops - describe operations for each V4L2 ioctl
 *
 * @vidioc_querycap: pointer to the function that implements
 *	:ref:`VIDIOC_QUERYCAP <vidioc_querycap>` ioctl
 * @vidioc_enum_fmt_vid_cap: pointer to the function that implements
 *	:ref:`VIDIOC_ENUM_FMT <vidioc_enum_fmt>` ioctl logic
 *	for video capture in single plane mode
 * @vidioc_enum_fmt_vid_overlay: pointer to the function that implements
 *	:ref:`VIDIOC_ENUM_FMT <vidioc_enum_fmt>` ioctl logic
 *	for video overlay
 * @vidioc_enum_fmt_vid_out: pointer to the function that implements
 *	:ref:`VIDIOC_ENUM_FMT <vidioc_enum_fmt>` ioctl logic
 *	for video output in single plane mode
 * @vidioc_enum_fmt_vid_cap_mplane: pointer to the function that implements
 *	:ref:`VIDIOC_ENUM_FMT <vidioc_enum_fmt>` ioctl logic
 *	for video capture in multiplane mode
 * @vidioc_enum_fmt_vid_out_mplane: pointer to the function that implements
 *	:ref:`VIDIOC_ENUM_FMT <vidioc_enum_fmt>` ioctl logic
 *	for video output in multiplane mode
 * @vidioc_enum_fmt_sdr_cap: pointer to the function that implements
 *	:ref:`VIDIOC_ENUM_FMT <vidioc_enum_fmt>` ioctl logic
 *	for Software Defined Radio capture
 * @vidioc_enum_fmt_sdr_out: pointer to the function that implements
 *	:ref:`VIDIOC_ENUM_FMT <vidioc_enum_fmt>` ioctl logic
 *	for Software Defined Radio output
 * @vidioc_g_fmt_vid_cap: pointer to the function that implements
 *	:ref:`VIDIOC_G_FMT <vidioc_g_fmt>` ioctl logic for video capture
 *	in single plane mode
 * @vidioc_g_fmt_vid_overlay: pointer to the function that implements
 *	:ref:`VIDIOC_G_FMT <vidioc_g_fmt>` ioctl logic for video overlay
 * @vidioc_g_fmt_vid_out: pointer to the function that implements
 *	:ref:`VIDIOC_G_FMT <vidioc_g_fmt>` ioctl logic for video out
 *	in single plane mode
 * @vidioc_g_fmt_vid_out_overlay: pointer to the function that implements
 *	:ref:`VIDIOC_G_FMT <vidioc_g_fmt>` ioctl logic for video overlay output
 * @vidioc_g_fmt_vbi_cap: pointer to the function that implements
 *	:ref:`VIDIOC_G_FMT <vidioc_g_fmt>` ioctl logic for raw VBI capture
 * @vidioc_g_fmt_vbi_out: pointer to the function that implements
 *	:ref:`VIDIOC_G_FMT <vidioc_g_fmt>` ioctl logic for raw VBI output
 * @vidioc_g_fmt_sliced_vbi_cap: pointer to the function that implements
 *	:ref:`VIDIOC_G_FMT <vidioc_g_fmt>` ioctl logic for sliced VBI capture
 * @vidioc_g_fmt_sliced_vbi_out: pointer to the function that implements
 *	:ref:`VIDIOC_G_FMT <vidioc_g_fmt>` ioctl logic for sliced VBI output
 * @vidioc_g_fmt_vid_cap_mplane: pointer to the function that implements
 *	:ref:`VIDIOC_G_FMT <vidioc_g_fmt>` ioctl logic for video capture
 *	in multiple plane mode
 * @vidioc_g_fmt_vid_out_mplane: pointer to the function that implements
 *	:ref:`VIDIOC_G_FMT <vidioc_g_fmt>` ioctl logic for video out
 *	in multiplane plane mode
 * @vidioc_g_fmt_sdr_cap: pointer to the function that implements
 *	:ref:`VIDIOC_G_FMT <vidioc_g_fmt>` ioctl logic for Software Defined
 *	Radio capture
 * @vidioc_g_fmt_sdr_out: pointer to the function that implements
 *	:ref:`VIDIOC_G_FMT <vidioc_g_fmt>` ioctl logic for Software Defined
 *	Radio output
 * @vidioc_s_fmt_vid_cap: pointer to the function that implements
 *	:ref:`VIDIOC_S_FMT <vidioc_g_fmt>` ioctl logic for video capture
 *	in single plane mode
 * @vidioc_s_fmt_vid_overlay: pointer to the function that implements
 *	:ref:`VIDIOC_S_FMT <vidioc_g_fmt>` ioctl logic for video overlay
 * @vidioc_s_fmt_vid_out: pointer to the function that implements
 *	:ref:`VIDIOC_S_FMT <vidioc_g_fmt>` ioctl logic for video out
 *	in single plane mode
 * @vidioc_s_fmt_vid_out_overlay: pointer to the function that implements
 *	:ref:`VIDIOC_S_FMT <vidioc_g_fmt>` ioctl logic for video overlay output
 * @vidioc_s_fmt_vbi_cap: pointer to the function that implements
 *	:ref:`VIDIOC_S_FMT <vidioc_g_fmt>` ioctl logic for raw VBI capture
 * @vidioc_s_fmt_vbi_out: pointer to the function that implements
 *	:ref:`VIDIOC_S_FMT <vidioc_g_fmt>` ioctl logic for raw VBI output
 * @vidioc_s_fmt_sliced_vbi_cap: pointer to the function that implements
 *	:ref:`VIDIOC_S_FMT <vidioc_g_fmt>` ioctl logic for sliced VBI capture
 * @vidioc_s_fmt_sliced_vbi_out: pointer to the function that implements
 *	:ref:`VIDIOC_S_FMT <vidioc_g_fmt>` ioctl logic for sliced VBI output
 * @vidioc_s_fmt_vid_cap_mplane: pointer to the function that implements
 *	:ref:`VIDIOC_S_FMT <vidioc_g_fmt>` ioctl logic for video capture
 *	in multiple plane mode
 * @vidioc_s_fmt_vid_out_mplane: pointer to the function that implements
 *	:ref:`VIDIOC_S_FMT <vidioc_g_fmt>` ioctl logic for video out
 *	in multiplane plane mode
 * @vidioc_s_fmt_sdr_cap: pointer to the function that implements
 *	:ref:`VIDIOC_S_FMT <vidioc_g_fmt>` ioctl logic for Software Defined
 *	Radio capture
 * @vidioc_s_fmt_sdr_out: pointer to the function that implements
 *	:ref:`VIDIOC_S_FMT <vidioc_g_fmt>` ioctl logic for Software Defined
 *	Radio output
 * @vidioc_try_fmt_vid_cap: pointer to the function that implements
 *	:ref:`VIDIOC_TRY_FMT <vidioc_g_fmt>` ioctl logic for video capture
 *	in single plane mode
 * @vidioc_try_fmt_vid_overlay: pointer to the function that implements
 *	:ref:`VIDIOC_TRY_FMT <vidioc_g_fmt>` ioctl logic for video overlay
 * @vidioc_try_fmt_vid_out: pointer to the function that implements
 *	:ref:`VIDIOC_TRY_FMT <vidioc_g_fmt>` ioctl logic for video out
 *	in single plane mode
 * @vidioc_try_fmt_vid_out_overlay: pointer to the function that implements
 *	:ref:`VIDIOC_TRY_FMT <vidioc_g_fmt>` ioctl logic for video overlay
 *	output
 * @vidioc_try_fmt_vbi_cap: pointer to the function that implements
 *	:ref:`VIDIOC_TRY_FMT <vidioc_g_fmt>` ioctl logic for raw VBI capture
 * @vidioc_try_fmt_vbi_out: pointer to the function that implements
 *	:ref:`VIDIOC_TRY_FMT <vidioc_g_fmt>` ioctl logic for raw VBI output
 * @vidioc_try_fmt_sliced_vbi_cap: pointer to the function that implements
 *	:ref:`VIDIOC_TRY_FMT <vidioc_g_fmt>` ioctl logic for sliced VBI
 *	capture
 * @vidioc_try_fmt_sliced_vbi_out: pointer to the function that implements
 *	:ref:`VIDIOC_TRY_FMT <vidioc_g_fmt>` ioctl logic for sliced VBI output
 * @vidioc_try_fmt_vid_cap_mplane: pointer to the function that implements
 *	:ref:`VIDIOC_TRY_FMT <vidioc_g_fmt>` ioctl logic for video capture
 *	in multiple plane mode
 * @vidioc_try_fmt_vid_out_mplane: pointer to the function that implements
 *	:ref:`VIDIOC_TRY_FMT <vidioc_g_fmt>` ioctl logic for video out
 *	in multiplane plane mode
 * @vidioc_try_fmt_sdr_cap: pointer to the function that implements
 *	:ref:`VIDIOC_TRY_FMT <vidioc_g_fmt>` ioctl logic for Software Defined
 *	Radio capture
 * @vidioc_try_fmt_sdr_out: pointer to the function that implements
 *	:ref:`VIDIOC_TRY_FMT <vidioc_g_fmt>` ioctl logic for Software Defined
 *	Radio output
 * @vidioc_reqbufs: pointer to the function that implements
 *	:ref:`VIDIOC_REQBUFS <vidioc_reqbufs>` ioctl
 * @vidioc_querybuf: pointer to the function that implements
 *	:ref:`VIDIOC_QUERYBUF <vidioc_querybuf>` ioctl
 * @vidioc_qbuf: pointer to the function that implements
 *	:ref:`VIDIOC_QBUF <vidioc_qbuf>` ioctl
 * @vidioc_expbuf: pointer to the function that implements
 *	:ref:`VIDIOC_EXPBUF <vidioc_expbuf>` ioctl
 * @vidioc_dqbuf: pointer to the function that implements
 *	:ref:`VIDIOC_DQBUF <vidioc_qbuf>` ioctl
 * @vidioc_create_bufs: pointer to the function that implements
 *	:ref:`VIDIOC_CREATE_BUFS <vidioc_create_bufs>` ioctl
 * @vidioc_prepare_buf: pointer to the function that implements
 *	:ref:`VIDIOC_PREPARE_BUF <vidioc_prepare_buf>` ioctl
 * @vidioc_overlay: pointer to the function that implements
 *	:ref:`VIDIOC_OVERLAY <vidioc_overlay>` ioctl
 * @vidioc_g_fbuf: pointer to the function that implements
 *	:ref:`VIDIOC_G_FBUF <vidioc_g_fbuf>` ioctl
 * @vidioc_s_fbuf: pointer to the function that implements
 *	:ref:`VIDIOC_S_FBUF <vidioc_g_fbuf>` ioctl
 * @vidioc_streamon: pointer to the function that implements
 *	:ref:`VIDIOC_STREAMON <vidioc_streamon>` ioctl
 * @vidioc_streamoff: pointer to the function that implements
 *	:ref:`VIDIOC_STREAMOFF <vidioc_streamon>` ioctl
 * @vidioc_g_std: pointer to the function that implements
 *	:ref:`VIDIOC_G_STD <vidioc_g_std>` ioctl
 * @vidioc_s_std: pointer to the function that implements
 *	:ref:`VIDIOC_S_STD <vidioc_g_std>` ioctl
 * @vidioc_querystd: pointer to the function that implements
 *	:ref:`VIDIOC_QUERYSTD <vidioc_querystd>` ioctl
 * @vidioc_enum_input: pointer to the function that implements
 *	:ref:`VIDIOC_ENUM_INPUT <vidioc_g_input>` ioctl
 * @vidioc_g_input: pointer to the function that implements
 *	:ref:`VIDIOC_G_INPUT <vidioc_g_input>` ioctl
 * @vidioc_s_input: pointer to the function that implements
 *	:ref:`VIDIOC_S_INPUT <vidioc_g_input>` ioctl
 * @vidioc_enum_output: pointer to the function that implements
 *	:ref:`VIDIOC_ENUM_OUTPUT <vidioc_g_output>` ioctl
 * @vidioc_g_output: pointer to the function that implements
 *	:ref:`VIDIOC_G_OUTPUT <vidioc_g_output>` ioctl
 * @vidioc_s_output: pointer to the function that implements
 *	:ref:`VIDIOC_S_OUTPUT <vidioc_g_output>` ioctl
 * @vidioc_queryctrl: pointer to the function that implements
 *	:ref:`VIDIOC_QUERYCTRL <vidioc_queryctrl>` ioctl
 * @vidioc_query_ext_ctrl: pointer to the function that implements
 *	:ref:`VIDIOC_QUERY_EXT_CTRL <vidioc_queryctrl>` ioctl
 * @vidioc_g_ctrl: pointer to the function that implements
 *	:ref:`VIDIOC_G_CTRL <vidioc_g_ctrl>` ioctl
 * @vidioc_s_ctrl: pointer to the function that implements
 *	:ref:`VIDIOC_S_CTRL <vidioc_g_ctrl>` ioctl
 * @vidioc_g_ext_ctrls: pointer to the function that implements
 *	:ref:`VIDIOC_G_EXT_CTRLS <vidioc_g_ext_ctrls>` ioctl
 * @vidioc_s_ext_ctrls: pointer to the function that implements
 *	:ref:`VIDIOC_S_EXT_CTRLS <vidioc_g_ext_ctrls>` ioctl
 * @vidioc_try_ext_ctrls: pointer to the function that implements
 *	:ref:`VIDIOC_TRY_EXT_CTRLS <vidioc_g_ext_ctrls>` ioctl
 * @vidioc_querymenu: pointer to the function that implements
 *	:ref:`VIDIOC_QUERYMENU <vidioc_queryctrl>` ioctl
 * @vidioc_enumaudio: pointer to the function that implements
 *	:ref:`VIDIOC_ENUMAUDIO <vidioc_enumaudio>` ioctl
 * @vidioc_g_audio: pointer to the function that implements
 *	:ref:`VIDIOC_G_AUDIO <vidioc_g_audio>` ioctl
 * @vidioc_s_audio: pointer to the function that implements
 *	:ref:`VIDIOC_S_AUDIO <vidioc_g_audio>` ioctl
 * @vidioc_enumaudout: pointer to the function that implements
 *	:ref:`VIDIOC_ENUMAUDOUT <vidioc_enumaudout>` ioctl
 * @vidioc_g_audout: pointer to the function that implements
 *	:ref:`VIDIOC_G_AUDOUT <vidioc_g_audout>` ioctl
 * @vidioc_s_audout: pointer to the function that implements
 *	:ref:`VIDIOC_S_AUDOUT <vidioc_g_audout>` ioctl
 * @vidioc_g_modulator: pointer to the function that implements
 *	:ref:`VIDIOC_G_MODULATOR <vidioc_g_modulator>` ioctl
 * @vidioc_s_modulator: pointer to the function that implements
 *	:ref:`VIDIOC_S_MODULATOR <vidioc_g_modulator>` ioctl
 * @vidioc_cropcap: pointer to the function that implements
 *	:ref:`VIDIOC_CROPCAP <vidioc_cropcap>` ioctl
 * @vidioc_g_crop: pointer to the function that implements
 *	:ref:`VIDIOC_G_CROP <vidioc_g_crop>` ioctl
 * @vidioc_s_crop: pointer to the function that implements
 *	:ref:`VIDIOC_S_CROP <vidioc_g_crop>` ioctl
 * @vidioc_g_selection: pointer to the function that implements
 *	:ref:`VIDIOC_G_SELECTION <vidioc_g_selection>` ioctl
 * @vidioc_s_selection: pointer to the function that implements
 *	:ref:`VIDIOC_S_SELECTION <vidioc_g_selection>` ioctl
 * @vidioc_g_jpegcomp: pointer to the function that implements
 *	:ref:`VIDIOC_G_JPEGCOMP <vidioc_g_jpegcomp>` ioctl
 * @vidioc_s_jpegcomp: pointer to the function that implements
 *	:ref:`VIDIOC_S_JPEGCOMP <vidioc_g_jpegcomp>` ioctl
 * @vidioc_g_enc_index: pointer to the function that implements
 *	:ref:`VIDIOC_G_ENC_INDEX <vidioc_g_enc_index>` ioctl
 * @vidioc_encoder_cmd: pointer to the function that implements
 *	:ref:`VIDIOC_ENCODER_CMD <vidioc_encoder_cmd>` ioctl
 * @vidioc_try_encoder_cmd: pointer to the function that implements
 *	:ref:`VIDIOC_TRY_ENCODER_CMD <vidioc_encoder_cmd>` ioctl
 * @vidioc_decoder_cmd: pointer to the function that implements
 *	:ref:`VIDIOC_DECODER_CMD <vidioc_decoder_cmd>` ioctl
 * @vidioc_try_decoder_cmd: pointer to the function that implements
 *	:ref:`VIDIOC_TRY_DECODER_CMD <vidioc_decoder_cmd>` ioctl
 * @vidioc_g_parm: pointer to the function that implements
 *	:ref:`VIDIOC_G_PARM <vidioc_g_parm>` ioctl
 * @vidioc_s_parm: pointer to the function that implements
 *	:ref:`VIDIOC_S_PARM <vidioc_g_parm>` ioctl
 * @vidioc_g_tuner: pointer to the function that implements
 *	:ref:`VIDIOC_G_TUNER <vidioc_g_tuner>` ioctl
 * @vidioc_s_tuner: pointer to the function that implements
 *	:ref:`VIDIOC_S_TUNER <vidioc_g_tuner>` ioctl
 * @vidioc_g_frequency: pointer to the function that implements
 *	:ref:`VIDIOC_G_FREQUENCY <vidioc_g_frequency>` ioctl
 * @vidioc_s_frequency: pointer to the function that implements
 *	:ref:`VIDIOC_S_FREQUENCY <vidioc_g_frequency>` ioctl
 * @vidioc_enum_freq_bands: pointer to the function that implements
 *	:ref:`VIDIOC_ENUM_FREQ_BANDS <vidioc_enum_freq_bands>` ioctl
 * @vidioc_g_sliced_vbi_cap: pointer to the function that implements
 *	:ref:`VIDIOC_G_SLICED_VBI_CAP <vidioc_g_sliced_vbi_cap>` ioctl
 * @vidioc_log_status: pointer to the function that implements
 *	:ref:`VIDIOC_LOG_STATUS <vidioc_log_status>` ioctl
 * @vidioc_s_hw_freq_seek: pointer to the function that implements
 *	:ref:`VIDIOC_S_HW_FREQ_SEEK <vidioc_s_hw_freq_seek>` ioctl
 * @vidioc_g_register: pointer to the function that implements
 *	:ref:`VIDIOC_DBG_G_REGISTER <vidioc_dbg_g_register>` ioctl
 * @vidioc_s_register: pointer to the function that implements
 *	:ref:`VIDIOC_DBG_S_REGISTER <vidioc_dbg_g_register>` ioctl
 * @vidioc_g_chip_info: pointer to the function that implements
 *	:ref:`VIDIOC_DBG_G_CHIP_INFO <vidioc_dbg_g_chip_info>` ioctl
 * @vidioc_enum_framesizes: pointer to the function that implements
 *	:ref:`VIDIOC_ENUM_FRAMESIZES <vidioc_enum_framesizes>` ioctl
 * @vidioc_enum_frameintervals: pointer to the function that implements
 *	:ref:`VIDIOC_ENUM_FRAMEINTERVALS <vidioc_enum_frameintervals>` ioctl
 * @vidioc_s_dv_timings: pointer to the function that implements
 *	:ref:`VIDIOC_S_DV_TIMINGS <vidioc_g_dv_timings>` ioctl
 * @vidioc_g_dv_timings: pointer to the function that implements
 *	:ref:`VIDIOC_G_DV_TIMINGS <vidioc_g_dv_timings>` ioctl
 * @vidioc_query_dv_timings: pointer to the function that implements
 *	:ref:`VIDIOC_QUERY_DV_TIMINGS <vidioc_query_dv_timings>` ioctl
 * @vidioc_enum_dv_timings: pointer to the function that implements
 *	:ref:`VIDIOC_ENUM_DV_TIMINGS <vidioc_enum_dv_timings>` ioctl
 * @vidioc_dv_timings_cap: pointer to the function that implements
 *	:ref:`VIDIOC_DV_TIMINGS_CAP <vidioc_dv_timings_cap>` ioctl
 * @vidioc_g_edid: pointer to the function that implements
 *	:ref:`VIDIOC_G_EDID <vidioc_g_edid>` ioctl
 * @vidioc_s_edid: pointer to the function that implements
 *	:ref:`VIDIOC_S_EDID <vidioc_g_edid>` ioctl
 * @vidioc_subscribe_event: pointer to the function that implements
 *	:ref:`VIDIOC_SUBSCRIBE_EVENT <vidioc_subscribe_event>` ioctl
 * @vidioc_unsubscribe_event: pointer to the function that implements
 *	:ref:`VIDIOC_UNSUBSCRIBE_EVENT <vidioc_unsubscribe_event>` ioctl
 * @vidioc_default: pointed used to allow other ioctls
 */
struct v4l2_ioctl_ops {
	/* ioctl callbacks */
	//这个函数处理 VIDIOC_QUERYCAP 的 ioctl(), 只是简单问问“你是谁？你能干什么？”实现它是 V4L2
	//驱动的责任。和所有其他 V4L2 回调函数一样，这个函数中的参数 priv 是 file->private_data 域的内容，通
	//常的做法是在 open()的时候把它指向驱动中表示设备的内部结构体�
	//驱动应该负责填充 cap 结构并且返回“0 或负的错误码”值。如果成功返回，则 V4L2 层会负责把回复拷
	//贝到用户空间
	/* VIDIOC_QUERYCAP handler */
	int (*vidioc_querycap)(struct file *file, void *fh,
			       struct v4l2_capability *cap);

	/* VIDIOC_ENUM_FMT handlers */
	int (*vidioc_enum_fmt_vid_cap)(struct file *file, void *fh,
				       struct v4l2_fmtdesc *f);
	int (*vidioc_enum_fmt_vid_overlay)(struct file *file, void *fh,
					   struct v4l2_fmtdesc *f);
	int (*vidioc_enum_fmt_vid_out)(struct file *file, void *fh,
				       struct v4l2_fmtdesc *f);
	int (*vidioc_enum_fmt_vid_cap_mplane)(struct file *file, void *fh,
					      struct v4l2_fmtdesc *f);
	int (*vidioc_enum_fmt_vid_out_mplane)(struct file *file, void *fh,
					      struct v4l2_fmtdesc *f);
	int (*vidioc_enum_fmt_sdr_cap)(struct file *file, void *fh,
				       struct v4l2_fmtdesc *f);
	int (*vidioc_enum_fmt_sdr_out)(struct file *file, void *fh,
				       struct v4l2_fmtdesc *f);

	/* VIDIOC_G_FMT handlers */
	int (*vidioc_g_fmt_vid_cap)(struct file *file, void *fh,
				    struct v4l2_format *f);
	int (*vidioc_g_fmt_vid_overlay)(struct file *file, void *fh,
					struct v4l2_format *f);
	int (*vidioc_g_fmt_vid_out)(struct file *file, void *fh,
				    struct v4l2_format *f);
	int (*vidioc_g_fmt_vid_out_overlay)(struct file *file, void *fh,
					    struct v4l2_format *f);
	int (*vidioc_g_fmt_vbi_cap)(struct file *file, void *fh,
				    struct v4l2_format *f);
	int (*vidioc_g_fmt_vbi_out)(struct file *file, void *fh,
				    struct v4l2_format *f);
	int (*vidioc_g_fmt_sliced_vbi_cap)(struct file *file, void *fh,
					   struct v4l2_format *f);
	int (*vidioc_g_fmt_sliced_vbi_out)(struct file *file, void *fh,
					   struct v4l2_format *f);
	int (*vidioc_g_fmt_vid_cap_mplane)(struct file *file, void *fh,
					   struct v4l2_format *f);
	int (*vidioc_g_fmt_vid_out_mplane)(struct file *file, void *fh,
					   struct v4l2_format *f);
	int (*vidioc_g_fmt_sdr_cap)(struct file *file, void *fh,
				    struct v4l2_format *f);
	int (*vidioc_g_fmt_sdr_out)(struct file *file, void *fh,
				    struct v4l2_format *f);

	/* VIDIOC_S_FMT handlers */
	int (*vidioc_s_fmt_vid_cap)(struct file *file, void *fh,
				    struct v4l2_format *f);
	int (*vidioc_s_fmt_vid_overlay)(struct file *file, void *fh,
					struct v4l2_format *f);
	int (*vidioc_s_fmt_vid_out)(struct file *file, void *fh,
				    struct v4l2_format *f);
	int (*vidioc_s_fmt_vid_out_overlay)(struct file *file, void *fh,
					    struct v4l2_format *f);
	int (*vidioc_s_fmt_vbi_cap)(struct file *file, void *fh,
				    struct v4l2_format *f);
	int (*vidioc_s_fmt_vbi_out)(struct file *file, void *fh,
				    struct v4l2_format *f);
	int (*vidioc_s_fmt_sliced_vbi_cap)(struct file *file, void *fh,
					   struct v4l2_format *f);
	int (*vidioc_s_fmt_sliced_vbi_out)(struct file *file, void *fh,
					   struct v4l2_format *f);
	int (*vidioc_s_fmt_vid_cap_mplane)(struct file *file, void *fh,
					   struct v4l2_format *f);
	int (*vidioc_s_fmt_vid_out_mplane)(struct file *file, void *fh,
					   struct v4l2_format *f);
	int (*vidioc_s_fmt_sdr_cap)(struct file *file, void *fh,
				    struct v4l2_format *f);
	int (*vidioc_s_fmt_sdr_out)(struct file *file, void *fh,
				    struct v4l2_format *f);

	/* VIDIOC_TRY_FMT handlers */
	int (*vidioc_try_fmt_vid_cap)(struct file *file, void *fh,
				      struct v4l2_format *f);
	int (*vidioc_try_fmt_vid_overlay)(struct file *file, void *fh,
					  struct v4l2_format *f);
	int (*vidioc_try_fmt_vid_out)(struct file *file, void *fh,
				      struct v4l2_format *f);
	int (*vidioc_try_fmt_vid_out_overlay)(struct file *file, void *fh,
					     struct v4l2_format *f);
	int (*vidioc_try_fmt_vbi_cap)(struct file *file, void *fh,
				      struct v4l2_format *f);
	int (*vidioc_try_fmt_vbi_out)(struct file *file, void *fh,
				      struct v4l2_format *f);
	int (*vidioc_try_fmt_sliced_vbi_cap)(struct file *file, void *fh,
					     struct v4l2_format *f);
	int (*vidioc_try_fmt_sliced_vbi_out)(struct file *file, void *fh,
					     struct v4l2_format *f);
	int (*vidioc_try_fmt_vid_cap_mplane)(struct file *file, void *fh,
					     struct v4l2_format *f);
	int (*vidioc_try_fmt_vid_out_mplane)(struct file *file, void *fh,
					     struct v4l2_format *f);
	int (*vidioc_try_fmt_sdr_cap)(struct file *file, void *fh,
				      struct v4l2_format *f);
	int (*vidioc_try_fmt_sdr_out)(struct file *file, void *fh,
				      struct v4l2_format *f);

	/* Buffer handlers */
	int (*vidioc_reqbufs)(struct file *file, void *fh,
			      struct v4l2_requestbuffers *b);
	int (*vidioc_querybuf)(struct file *file, void *fh,
			       struct v4l2_buffer *b);
	int (*vidioc_qbuf)(struct file *file, void *fh,
			   struct v4l2_buffer *b);
	int (*vidioc_expbuf)(struct file *file, void *fh,
			     struct v4l2_exportbuffer *e);
	int (*vidioc_dqbuf)(struct file *file, void *fh,
			    struct v4l2_buffer *b);

	int (*vidioc_create_bufs)(struct file *file, void *fh,
				  struct v4l2_create_buffers *b);
	int (*vidioc_prepare_buf)(struct file *file, void *fh,
				  struct v4l2_buffer *b);

	int (*vidioc_overlay)(struct file *file, void *fh, unsigned int i);
	int (*vidioc_g_fbuf)(struct file *file, void *fh,
			     struct v4l2_framebuffer *a);
	int (*vidioc_s_fbuf)(struct file *file, void *fh,
			     const struct v4l2_framebuffer *a);

		/* Stream on/off */
	int (*vidioc_streamon)(struct file *file, void *fh,
			       enum v4l2_buf_type i);
	int (*vidioc_streamoff)(struct file *file, void *fh,
				enum v4l2_buf_type i);



/*
对于用户空间而言，V4L2 提供一个 ioctl()命令(VIDIOC_ENUMSTD)，它允许应用查询设备实现了哪
些标准。驱动却无需直接回答查询，而是将 video_device 结构体的 tvnorm 字段设置为它所支持的所有标准。
然后 V4L2 层会向应用回复所支持的标准。VIDIOC_G_STD 命令可以用来查询现在哪种标准是激活的，它
也是在 V4L2 层通过返回 video_device 结构的 current_norm 字段来处理的。驱动程序应在启动时，初始化
current_norm 来反映现实情况。有些应用即使他并没有设置过标准，发现标准没有被设置也会感到困惑。
当某个应用想要申请某个特定标准时，会发出一个 VIDIOC_S_STD 调用，该调用传到驱动时通过下面
的回调函数实现：
				int (*vidioc_s_std) (struct file *file, void *private_data, v4l2_std_id std);
驱动要对硬件编程，以使用特定的标准，并返回 0(或是负的错误码）。V4L2 层需要把 current_norm 设
为新的值
/*

		/*
		 * Standard handling
		 *
		 * Note: ENUMSTD is handled by videodev.c
		 */
	int (*vidioc_g_std)(struct file *file, void *fh, v4l2_std_id *norm);
	//V4L2 使用 v4l2_std_id 来代表视频标准，它是一个 64 位的掩码。每个标准变种在掩码中就是一位
	int (*vidioc_s_std)(struct file *file, void *fh, v4l2_std_id norm);
/*
应用可能想要知道硬件所看到的是何种信号，答案可以通过 VIDIOC_QUERYSTD 找到，它到了驱动里
面就是：
int (*vidioc_querystd) (struct file *file, void *private_data, v4l2_std_id *std);
*/
	int (*vidioc_querystd)(struct file *file, void *fh, v4l2_std_id *a);
/*
视频捕获的应用首先要通过 VIDIOC_ENUMINPUT 命令来枚举所有可用的输入
在 V4L2 层，这个调用会转换成调用驱动中对应的回调函数：
int (*vidioc_enum_input)(struct file *file, void *private_data, struct v4l2_input *input);
在这个调用中，file 对应要打开的视频设备。private_data 是驱动的私有字段。input 字段是传递的真正
信息，它有如下几个值得关注的字段
*/
		/* Input handling */
	int (*vidioc_enum_input)(struct file *file, void *fh,
				 struct v4l2_input *inp);
/*
指示哪一个输入处在激活状态
int (*vidioc_g_input) (struct file *file, void *private_data, unsigned int *index);
这里驱动把*index 值设为当前激活输入的索引号
*/
	int (*vidioc_g_input)(struct file *file, void *fh, unsigned int *i);
/*
当应用想改变当前输入时，驱动会收到一个对回调函数 vidioc_s_input()的调用。
也有可能要返回-EINVAL(索引号不正确) 或-EIO(硬件故障)。即使只有一路输入，驱动也要实现这个回调函数
i的值与上面讲到的意义相同——它用来确定哪个输入是想要的。
驱动要对硬件操作，选择指定输入并返回 0
也有可能要返回-EINVAL(索引号不正确) 或-EIO(硬件故障)。即使只有一路输入，驱动也要实
现这个回调函数
*/
	int (*vidioc_s_input)(struct file *file, void *fh, unsigned int i);
/*
输出枚举的回调函数是这样的
*/
		/* Output handling */
	int (*vidioc_enum_output)(struct file *file, void *fh,
				  struct v4l2_output *a);
/*
也有用于获得和设定现行输出  设置的回调函数，他们与输入的回调对应
*/
	int (*vidioc_g_output)(struct file *file, void *fh, unsigned int *i);
	int (*vidioc_s_output)(struct file *file, void *fh, unsigned int i);

		/* Control handling */
	int (*vidioc_queryctrl)(struct file *file, void *fh,
				struct v4l2_queryctrl *a);
	int (*vidioc_query_ext_ctrl)(struct file *file, void *fh,
				     struct v4l2_query_ext_ctrl *a);
	int (*vidioc_g_ctrl)(struct file *file, void *fh,
			     struct v4l2_control *a);
	int (*vidioc_s_ctrl)(struct file *file, void *fh,
			     struct v4l2_control *a);
	int (*vidioc_g_ext_ctrls)(struct file *file, void *fh,
				  struct v4l2_ext_controls *a);
	int (*vidioc_s_ext_ctrls)(struct file *file, void *fh,
				  struct v4l2_ext_controls *a);
	int (*vidioc_try_ext_ctrls)(struct file *file, void *fh,
				    struct v4l2_ext_controls *a);
	int (*vidioc_querymenu)(struct file *file, void *fh,
				struct v4l2_querymenu *a);

	/* Audio ioctls */
	int (*vidioc_enumaudio)(struct file *file, void *fh,
				struct v4l2_audio *a);
	int (*vidioc_g_audio)(struct file *file, void *fh,
			      struct v4l2_audio *a);
	int (*vidioc_s_audio)(struct file *file, void *fh,
			      const struct v4l2_audio *a);

	/* Audio out ioctls */
	int (*vidioc_enumaudout)(struct file *file, void *fh,
				 struct v4l2_audioout *a);
	int (*vidioc_g_audout)(struct file *file, void *fh,
			       struct v4l2_audioout *a);
	int (*vidioc_s_audout)(struct file *file, void *fh,
			       const struct v4l2_audioout *a);
	int (*vidioc_g_modulator)(struct file *file, void *fh,
				  struct v4l2_modulator *a);
	int (*vidioc_s_modulator)(struct file *file, void *fh,
				  const struct v4l2_modulator *a);
	/* Crop ioctls */
	int (*vidioc_cropcap)(struct file *file, void *fh,
			      struct v4l2_cropcap *a);
	int (*vidioc_g_crop)(struct file *file, void *fh,
			     struct v4l2_crop *a);
	int (*vidioc_s_crop)(struct file *file, void *fh,
			     const struct v4l2_crop *a);
	int (*vidioc_g_selection)(struct file *file, void *fh,
				  struct v4l2_selection *s);
	int (*vidioc_s_selection)(struct file *file, void *fh,
				  struct v4l2_selection *s);
	/* Compression ioctls */
	int (*vidioc_g_jpegcomp)(struct file *file, void *fh,
				 struct v4l2_jpegcompression *a);
	int (*vidioc_s_jpegcomp)(struct file *file, void *fh,
				 const struct v4l2_jpegcompression *a);
	int (*vidioc_g_enc_index)(struct file *file, void *fh,
				  struct v4l2_enc_idx *a);
	int (*vidioc_encoder_cmd)(struct file *file, void *fh,
				  struct v4l2_encoder_cmd *a);
	int (*vidioc_try_encoder_cmd)(struct file *file, void *fh,
				      struct v4l2_encoder_cmd *a);
	int (*vidioc_decoder_cmd)(struct file *file, void *fh,
				  struct v4l2_decoder_cmd *a);
	int (*vidioc_try_decoder_cmd)(struct file *file, void *fh,
				      struct v4l2_decoder_cmd *a);

	/* Stream type-dependent parameter ioctls */
	int (*vidioc_g_parm)(struct file *file, void *fh,
			     struct v4l2_streamparm *a);
	int (*vidioc_s_parm)(struct file *file, void *fh,
			     struct v4l2_streamparm *a);

	/* Tuner ioctls */
	int (*vidioc_g_tuner)(struct file *file, void *fh,
			      struct v4l2_tuner *a);
	int (*vidioc_s_tuner)(struct file *file, void *fh,
			      const struct v4l2_tuner *a);
	int (*vidioc_g_frequency)(struct file *file, void *fh,
				  struct v4l2_frequency *a);
	int (*vidioc_s_frequency)(struct file *file, void *fh,
				  const struct v4l2_frequency *a);
	int (*vidioc_enum_freq_bands)(struct file *file, void *fh,
				      struct v4l2_frequency_band *band);

	/* Sliced VBI cap */
	int (*vidioc_g_sliced_vbi_cap)(struct file *file, void *fh,
				       struct v4l2_sliced_vbi_cap *a);

//这个函数用来实现 VIDIOC_LOG_STATUS 调用，作为视频应用程序编写者的调试助手。当调用时，
//它应该打印描述驱动及其硬件的当前状态信息。这个信息应该足够充分以便帮助迷糊的应用程序开发者弄
//明白为什么视频显示一片空白。
	/* Log status ioctl */
	int (*vidioc_log_status)(struct file *file, void *fh);

	int (*vidioc_s_hw_freq_seek)(struct file *file, void *fh,
				     const struct v4l2_hw_freq_seek *a);

	/* Debugging ioctls */
#ifdef CONFIG_VIDEO_ADV_DEBUG
	int (*vidioc_g_register)(struct file *file, void *fh,
				 struct v4l2_dbg_register *reg);
	int (*vidioc_s_register)(struct file *file, void *fh,
				 const struct v4l2_dbg_register *reg);

	int (*vidioc_g_chip_info)(struct file *file, void *fh,
				  struct v4l2_dbg_chip_info *chip);
#endif

	int (*vidioc_enum_framesizes)(struct file *file, void *fh,
				      struct v4l2_frmsizeenum *fsize);

	int (*vidioc_enum_frameintervals)(struct file *file, void *fh,
					  struct v4l2_frmivalenum *fival);

	/* DV Timings IOCTLs */
	int (*vidioc_s_dv_timings)(struct file *file, void *fh,
				   struct v4l2_dv_timings *timings);
	int (*vidioc_g_dv_timings)(struct file *file, void *fh,
				   struct v4l2_dv_timings *timings);
	int (*vidioc_query_dv_timings)(struct file *file, void *fh,
				       struct v4l2_dv_timings *timings);
	int (*vidioc_enum_dv_timings)(struct file *file, void *fh,
				      struct v4l2_enum_dv_timings *timings);
	int (*vidioc_dv_timings_cap)(struct file *file, void *fh,
				     struct v4l2_dv_timings_cap *cap);
	int (*vidioc_g_edid)(struct file *file, void *fh,
			     struct v4l2_edid *edid);
	int (*vidioc_s_edid)(struct file *file, void *fh,
			     struct v4l2_edid *edid);

	int (*vidioc_subscribe_event)(struct v4l2_fh *fh,
				      const struct v4l2_event_subscription *sub);
	int (*vidioc_unsubscribe_event)(struct v4l2_fh *fh,
					const struct v4l2_event_subscription *sub);

	/* For other private ioctls */
	long (*vidioc_default)(struct file *file, void *fh,
			       bool valid_prio, unsigned int cmd, void *arg);
};


/* v4l debugging and diagnostics */

/* Device debug flags to be used with the video device debug attribute */

/* Just log the ioctl name + error code */
#define V4L2_DEV_DEBUG_IOCTL		0x01
/* Log the ioctl name arguments + error code */
#define V4L2_DEV_DEBUG_IOCTL_ARG	0x02
/* Log the file operations open, release, mmap and get_unmapped_area */
#define V4L2_DEV_DEBUG_FOP		0x04
/* Log the read and write file operations and the VIDIOC_(D)QBUF ioctls */
#define V4L2_DEV_DEBUG_STREAMING	0x08
/* Log poll() */
#define V4L2_DEV_DEBUG_POLL		0x10

/*  Video standard functions  */

/**
 * v4l2_norm_to_name - Ancillary routine to analog TV standard name from its ID.
 *
 * @id:	analog TV standard ID.
 *
 * Return: returns a string with the name of the analog TV standard.
 * If the standard is not found or if @id points to multiple standard,
 * it returns "Unknown".
 */
const char *v4l2_norm_to_name(v4l2_std_id id);

/**
 * v4l2_video_std_frame_period - Ancillary routine that fills a
 *	struct &v4l2_fract pointer with the default framerate fraction.
 *
 * @id: analog TV sdandard ID.
 * @frameperiod: struct &v4l2_fract pointer to be filled
 *
 */
void v4l2_video_std_frame_period(int id, struct v4l2_fract *frameperiod);

/**
 * v4l2_video_std_construct - Ancillary routine that fills in the fields of
 *	a &v4l2_standard structure according to the @id parameter.
 *
 * @vs: struct &v4l2_standard pointer to be filled
 * @id: analog TV sdandard ID.
 * @name: name of the standard to be used
 *
 * .. note::
 *
 *    This ancillary routine is obsolete. Shouldn't be used on newer drivers.
 */
int v4l2_video_std_construct(struct v4l2_standard *vs,
				    int id, const char *name);

/**
 * v4l_printk_ioctl - Ancillary routine that prints the ioctl in a
 *	human-readable format.
 *
 * @prefix: prefix to be added at the ioctl prints.
 * @cmd: ioctl name
 *
 * .. note::
 *
 *    If prefix != %NULL, then it will issue a
 *    ``printk(KERN_DEBUG "%s: ", prefix)`` first.
 */
void v4l_printk_ioctl(const char *prefix, unsigned int cmd);

struct video_device;


/**
 * v4l2_ioctl_get_lock - get the mutex (if any) that it is need to lock for
 *	a given command.
 *
 * @vdev: Pointer to struct &video_device.
 * @cmd: Ioctl name.
 *
 * .. note:: Internal use only. Should not be used outside V4L2 core.
 */
struct mutex *v4l2_ioctl_get_lock(struct video_device *vdev, unsigned int cmd);

/* names for fancy debug output */
extern const char *v4l2_field_names[];
extern const char *v4l2_type_names[];

#ifdef CONFIG_COMPAT
/**
 * v4l2_compat_ioctl32 -32 Bits compatibility layer for 64 bits processors
 *
 * @file: Pointer to struct &file.
 * @cmd: Ioctl name.
 * @arg: Ioctl argument.
 */
long int v4l2_compat_ioctl32(struct file *file, unsigned int cmd,
			     unsigned long arg);
#endif

/**
 * typedef v4l2_kioctl - Typedef used to pass an ioctl handler.
 *
 * @file: Pointer to struct &file.
 * @cmd: Ioctl name.
 * @arg: Ioctl argument.
 */
typedef long (*v4l2_kioctl)(struct file *file, unsigned int cmd, void *arg);

/**
 * video_usercopy - copies data from/to userspace memory when an ioctl is
 *	issued.
 *
 * @file: Pointer to struct &file.
 * @cmd: Ioctl name.
 * @arg: Ioctl argument.
 * @func: function that will handle the ioctl
 *
 * .. note::
 *
 *    This routine should be used only inside the V4L2 core.
 */
long int video_usercopy(struct file *file, unsigned int cmd,
			unsigned long int arg, v4l2_kioctl func);

/**
 * video_ioctl2 - Handles a V4L2 ioctl.
 *
 * @file: Pointer to struct &file.
 * @cmd: Ioctl name.
 * @arg: Ioctl argument.
 *
 * Method used to hancle an ioctl. Should be used to fill the
 * &v4l2_ioctl_ops.unlocked_ioctl on all V4L2 drivers.
 */
long int video_ioctl2(struct file *file,
		      unsigned int cmd, unsigned long int arg);

#endif /* _V4L2_IOCTL_H */
