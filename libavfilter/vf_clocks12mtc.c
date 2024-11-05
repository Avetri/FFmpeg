#include <libavutil/avassert.h>
#include "libavutil/common.h"
#include "libavutil/internal.h"
#include "libavutil/opt.h"
#include "libavutil/time.h"
#include "libavutil/timecode.h"
#include "avfilter.h"
#include "internal.h"
#include "video.h"
#include "libavutil/rational.h"

typedef struct ClockS12mTcContext {
    const AVClass *class;

    int replace_tc;
    int shift_ms;
    int local_time;
    AVRational rate;
    double d_rate;
    int64_t frame_us;
    int64_t frame_max_us;
    int64_t frame_min_us;
    int64_t time_start;
    int64_t time_last;
    int64_t pts_start;
    int64_t pts_last;
    int current_frame;
    int start_frame;
    int day_frames;

    char tcbuf[AV_TIMECODE_STR_SIZE];

} ClockS12mTcContext;

#define OFFSET(x) offsetof(ClockS12mTcContext, x)
#define FLAGS AV_OPT_FLAG_VIDEO_PARAM|AV_OPT_FLAG_FILTERING_PARAM

static const AVOption clocks12mtc_options[] = {
    /*
    { "replace_tc", "", OFFSET(replace_tc), AV_OPT_TYPE_BOOL, { .i64 = 1 }, 0, 1, FLAGS },
    { "local_time", "", OFFSET(local_time), AV_OPT_TYPE_BOOL, { .i64 = 0 }, 0, 1, FLAGS },
    */
    { "shift_ms", "", OFFSET(shift_ms), AV_OPT_TYPE_INT, {.i64 = 0 }, -10000, 10000, FLAGS },
    { NULL }
};

AVFILTER_DEFINE_CLASS(clocks12mtc);

static av_cold int init(AVFilterContext *ctx)
{
    /*
    ClockS12mTcContext *s = ctx->priv;
    */

    return 0;
}

static int config_props(AVFilterLink *inlink)
{
    AVFilterContext *ctx = inlink->dst;
    ClockS12mTcContext *s = ctx->priv;

    s->rate = inlink->frame_rate;
    av_assert0(0 != s->rate.den);
    s->d_rate = (double)s->rate.num/(double)s->rate.den;
    s->frame_us = (1000000*s->rate.den)/s->rate.num;
    s->frame_max_us = s->frame_us*3/2;
    s->frame_min_us = s->frame_us*2/3;
    s->day_frames = (int)(60.0*60.0*24.0*s->d_rate);
    s->time_last = LLONG_MAX;

    av_log(ctx, AV_LOG_DEBUG, "frame_rate: %f replace_tc:%d local_time:%d shift_ms:%d\n",
            av_q2d(s->rate), s->replace_tc, s->local_time, s->shift_ms);
    return 0;
}

static int filter_frame(AVFilterLink *inlink, AVFrame *frame)
{
    AVFilterContext *ctx = inlink->dst;
    AVFilterLink *outlink = ctx->outputs[0];
    ClockS12mTcContext *s = ctx->priv;

    AVTimecode tcr;
    int hh, mm, ss, ff;
    int err;
    int64_t pts_cur = av_rescale_q(frame->pts, inlink->time_base, frame->time_base);
    int64_t time_cur = (av_gettime()+(s->shift_ms*1000))%(1000000ll*3600ll*24ll);
    static int cnt = 0;
    if ((abs(pts_cur-s->pts_last) > s->frame_max_us) || (abs(pts_cur-s->pts_last) < s->frame_min_us)) {
        s->pts_start = pts_cur;
        s->time_start = time_cur;
        s->current_frame = 0;
        s->start_frame = s->current_frame;
        av_log(ctx, AV_LOG_INFO, "Reinit start time on PTS.");
    } else if (time_cur < s->time_last) {
        //TODO: Arrange tail day frames
        s->pts_start = pts_cur;
        s->time_start = time_cur;
        s->current_frame = 0;
        s->start_frame = s->current_frame;
        av_log(ctx, AV_LOG_INFO, "Reinit start time on time rotation.");
    } else {
        s->current_frame += 1;
    }
    cnt++;
    s->pts_last = pts_cur;
    s->time_last = time_cur;

    ss = s->time_start/1000000ll;
    ff = s->current_frame;
    hh = ss/3600;
    ss = ss-(hh*3600);
    mm = ss/60;
    ss = ss-(mm*60);

    err = av_timecode_init_from_components(&tcr, s->rate, AV_TIMECODE_FLAG_24HOURSMAX, hh, mm, ss, ff, ctx);

    if (0 == err) {
        char tcstr[AV_TIMECODE_STR_SIZE];
        const char *tc = av_timecode_make_string(&tcr, tcstr, 0);
        if (tc) {
            if (av_cmp_q(inlink->frame_rate, av_make_q(60, 1)) < 1) {
                uint32_t tc_data = av_timecode_get_smpte_from_framenum(&tcr, 0);
                int size = sizeof(uint32_t) * 4;
                AVFrameSideData *sd = av_frame_new_side_data(frame, AV_FRAME_DATA_S12M_TIMECODE, size);
                memset(sd->data, 0, size);

                if (NULL != sd) {
                    ((uint32_t*)sd->data)[0] = 1;       // one TC
                    ((uint32_t*)sd->data)[1] = tc_data; // TC
                } else {
                    av_log(ctx, AV_LOG_ERROR, "s12m timecode side data adding error.");
                }
            }

            if (av_dict_set(&frame->metadata, "timecode", tc, 0) < 0) {
                av_log(ctx, AV_LOG_ERROR, "'timecode' metadata adding error.");
            }
        }
    } else {
        av_log(ctx, AV_LOG_ERROR, "timecode initialization error: %d", err);
    }

    return ff_filter_frame(outlink, frame);
}

static const AVFilterPad inputs[] = {
    {
        .name         = "default",
        .type         = AVMEDIA_TYPE_VIDEO,
        .filter_frame = filter_frame,
        .config_props = config_props,
    },
};

const AVFilter ff_vf_clocks12mtc = {
    .name          = "clocks12mtc",
    .description   = NULL_IF_CONFIG_SMALL("Generate s12m timecode for encoder and metadata:timecode for drawtext filter."),
    .priv_size     = sizeof(ClockS12mTcContext),
    .priv_class    = &clocks12mtc_class,
    .flags         = AVFILTER_FLAG_METADATA_ONLY,
    FILTER_INPUTS(inputs),
    FILTER_OUTPUTS(ff_video_default_filterpad),
    .init          = init,
};
