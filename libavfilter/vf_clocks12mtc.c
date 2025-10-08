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

#include <time.h>

typedef struct ClockS12mTcContext {
    const AVClass *class;

    int replace_tc;
    int frame_drift;
    int shift_ms;
    int local_time;
    AVRational rate;
    double d_rate;
    int64_t frame_us;
    int64_t frame_max_us;
    int64_t frame_min_us;
    int64_t dtime_start_s;
    int64_t ts_start_us;
    int64_t ts_last_us;
    int64_t pts_start;
    int64_t pts_last;
    int64_t current_frame_ts_us;
    int current_frame;
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
    { "frame_drift", "", OFFSET(frame_drift), AV_OPT_TYPE_INT, {.i64 = 5 }, 0, 25, FLAGS },
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
    s->ts_last_us = LLONG_MAX;

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
    int64_t pts_d, ts_us_d, ff_d;
    int64_t pts_cur = av_rescale_q(frame->pts, inlink->time_base, frame->time_base);
    int64_t ts_us = av_gettime()-(s->shift_ms*1000ll);
    time_t ts_s = (time_t)ts_us/1000000ll;
    int32_t dtime_cur_s;
    int64_t dtime_cur_us;
    {
        struct tm tm;
        gmtime_r(&ts_s, &tm);
        dtime_cur_s = tm.tm_hour*3600 + tm.tm_min*60 + tm.tm_sec;
        dtime_cur_us = (dtime_cur_s*1000000ll) + (ts_us%1000000ll);
    }
    pts_d = ((pts_cur-s->pts_last)*1000000ll)/frame->time_base.den;
    ts_us_d = ts_us-s->ts_last_us;
    ff_d = (ts_us-s->ts_start_us)/s->frame_us - s->current_frame;
    if ((pts_d > s->frame_max_us) || (pts_d <= 0) ||
        (abs(ff_d) > s->frame_drift+1) ||
        (ts_us_d > 1000000) || (ts_us_d <= 0)) {
        s->ts_start_us = ts_us-dtime_cur_us;
        s->pts_start = pts_cur;
        s->dtime_start_s = 0;
        s->current_frame = dtime_cur_us/s->frame_us;
        s->current_frame_ts_us = ts_us;
        av_log(ctx, AV_LOG_INFO, "Reinit TC due to PTS(%" PRId64 ")/time(%" PRId64 ")/FF(%" PRId64 ") differencies inconsistency.\n", pts_d, ts_us_d, ff_d);
    } else {
        s->current_frame += 1;
        s->current_frame_ts_us += pts_d;
    }
    s->pts_last = pts_cur;
    s->ts_last_us = ts_us;

    ss = s->dtime_start_s;
    ff = s->current_frame;
    hh = ss/3600;
    ss = ss-(hh*3600);
    mm = ss/60;
    ss = ss-(mm*60);

    err = av_timecode_init_from_components(&tcr, s->rate, AV_TIMECODE_FLAG_24HOURSMAX, hh, mm, ss, ff, ctx);

    {
        int64_t ts_ms = s->current_frame_ts_us/1000;
        time_t ts_s = ts_ms/1000;
        struct tm tm;
        char tsstr[24]; // YYYY.mm.dd HH:MM:SS.fff
        gmtime_r(&ts_s, &tm);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
        snprintf(tsstr, sizeof(tsstr), "%04d.%02d.%02d %02d:%02d:%02d.%03d", tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, (int)(ts_ms%1000ll));
#pragma GCC diagnostic pop
        if (av_dict_set(&frame->metadata, "timestamp_ms", tsstr, 0) < 0) {
            av_log(ctx, AV_LOG_ERROR, "'timestamp_ms' metadata adding error.\n");
        }
    }

    if (0 == err) {
        char tcstr[AV_TIMECODE_STR_SIZE];
        char tcmsstr[AV_TIMECODE_STR_SIZE];
        const char *tc = av_timecode_make_string(&tcr, tcstr, 0);
        const char *tc_ms = av_timecode_make_string_ms(&tcr, tcmsstr, 0);
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
                    av_log(ctx, AV_LOG_ERROR, "s12m timecode side data adding error.\n");
                }
            }

            if (av_dict_set(&frame->metadata, "timecode", tc, 0) < 0) {
                av_log(ctx, AV_LOG_ERROR, "'timecode' metadata adding error.\n");
            }
            if (av_dict_set(&frame->metadata, "timecode_ms", tc_ms, 0) < 0) {
                av_log(ctx, AV_LOG_ERROR, "'timecode_ms' metadata adding error.\n");
            }
        }
    } else {
        av_log(ctx, AV_LOG_ERROR, "timecode initialization error: %d\n", err);
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
