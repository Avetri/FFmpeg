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
#include "libavutil/uuid.h"

#include <time.h>

typedef struct ClockS12mTcContext {
    const AVClass *class;

    int replace_tc;
    int frame_drift;
    int shift_ms;
    int local_time;
    int udu_sei;
    char * udu_sei_uuid_str;
    char * udu_sei_uuid;
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
    int current_frame_raw;
    int current_frame_diff;
    int day_frames;

    char tcbuf[AV_TIMECODE_STR_SIZE];

} ClockS12mTcContext;

#define OFFSET(x) offsetof(ClockS12mTcContext, x)
#define FLAGS AV_OPT_FLAG_VIDEO_PARAM|AV_OPT_FLAG_FILTERING_PARAM

#define UDU_SEI_NONE 0
#define UDU_SEI_JSON 1
#define UDU_SEI_LAST UDU_SEI_JSON

static const AVOption clocks12mtc_options[] = {
    /*
    { "replace_tc", "", OFFSET(replace_tc), AV_OPT_TYPE_BOOL, { .i64 = 1 }, 0, 1, FLAGS },
    { "local_time", "", OFFSET(local_time), AV_OPT_TYPE_BOOL, { .i64 = 0 }, 0, 1, FLAGS },
    */
    { "frame_drift", "", OFFSET(frame_drift), AV_OPT_TYPE_INT, {.i64 = 5 }, 0, 25, FLAGS },
    { "shift_ms", "", OFFSET(shift_ms), AV_OPT_TYPE_INT, {.i64 = 0 }, -10000, 10000, FLAGS },
    { "udu_sei", "TC UDU SEI format", OFFSET(udu_sei), AV_OPT_TYPE_INT, { .i64 = UDU_SEI_NONE}, UDU_SEI_NONE, UDU_SEI_LAST, FLAGS, .unit = "udu_sei"},
    { "none", "No timecode UDU SEI data generation", 0, AV_OPT_TYPE_CONST, {.i64 = UDU_SEI_NONE}, 0, 0, FLAGS, .unit = "udu_sei"},
    { "json", "JSON timecode UDU SEI data format", 0, AV_OPT_TYPE_CONST, { .i64 = UDU_SEI_JSON}, 0, 0, FLAGS, .unit = "udu_sei"},
    { "udu_sei_uuid", "SEI UUID for the data" , OFFSET(udu_sei_uuid_str),  AV_OPT_TYPE_STRING, { .str = NULL}, 0, 0, FLAGS },
    { NULL }
};

AVFILTER_DEFINE_CLASS(clocks12mtc);

static av_cold int init(AVFilterContext *ctx)
{
    ClockS12mTcContext *s = ctx->priv;

    if (UDU_SEI_NONE != s->udu_sei) {
        if (NULL == s->udu_sei_uuid_str) {
            av_log(ctx, AV_LOG_ERROR, "SEI UUID wasn't set.\n");
            return AVERROR(EINVAL);
        } else {
            AVUUID uuid;
            if (0 == av_uuid_parse(s->udu_sei_uuid_str, uuid)) {
                s->udu_sei_uuid = av_memdup(uuid, AV_UUID_LEN);
            } else {
                av_log(ctx, AV_LOG_ERROR, "SEI UUID \"%s\" wasn't parsed.\n", s->udu_sei_uuid_str);
                return AVERROR(EINVAL);
            }
        }
    }

    return 0;
}

static av_cold void uninit(AVFilterContext *ctx)
{
    ClockS12mTcContext *s = ctx->priv;

    if (NULL != s->udu_sei_uuid) {
        av_freep(&s->udu_sei_uuid);
    }
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
    s->current_frame_raw = INT_MAX;

    av_log(ctx, AV_LOG_DEBUG, "frame_rate: %f replace_tc:%d local_time:%d shift_ms:%d\n",
            av_q2d(s->rate), s->replace_tc, s->local_time, s->shift_ms);
    return 0;
}

static int filter_frame(AVFilterLink *inlink, AVFrame *frame)
{
    AVFilterContext *ctx = inlink->dst;
    AVFilterLink *outlink = ctx->outputs[0];
    ClockS12mTcContext *s = ctx->priv;

    AVTimecode tcr, tcr_raw;
    int hh, mm, ss, ff;
    int err;
    int64_t pts_d, ts_us_d, ff_d;
    int64_t pts_cur = av_rescale_q(frame->pts, inlink->time_base, frame->time_base);
    int64_t ts_us_raw = av_gettime();
    int64_t ts_us = ts_us_raw-(s->shift_ms*1000ll);
    time_t ts_s = (time_t)ts_us/1000000ll;
    int32_t dtime_cur_s;
    int64_t dtime_cur_us;
    {
        struct tm tm;
        gmtime_r(&ts_s, &tm);
        dtime_cur_s = tm.tm_hour*3600 + tm.tm_min*60 + tm.tm_sec;
        dtime_cur_us = (dtime_cur_s*1000000ll) + (ts_us%1000000ll);
    }
    if (INT_MAX != s->current_frame_raw) {
        s->current_frame_raw += 1;
    } else {
        s->current_frame_raw = dtime_cur_us/s->frame_us;
    }
    pts_d = ((pts_cur-s->pts_last)*1000000ll)/frame->time_base.den;
    ts_us_d = ts_us-s->ts_last_us;
    ff_d = (ts_us-s->ts_start_us)/s->frame_us - (s->current_frame_raw + s->current_frame_diff);
    if ((pts_d > s->frame_max_us) || (pts_d <= 0) ||
        (abs(ff_d) > s->frame_drift+1) ||
        (ts_us_d > 1000000) || (ts_us_d <= 0)) {
        s->ts_start_us = ts_us-dtime_cur_us;
        s->pts_start = pts_cur;
        s->dtime_start_s = 0;
        s->current_frame_diff = (dtime_cur_us/s->frame_us) - s->current_frame_raw;
        s->current_frame_ts_us = ts_us;
        av_log(ctx, AV_LOG_INFO, "Reinit TC due to PTS(%" PRId64 ")/time(%" PRId64 ")/FF(%" PRId64 ") differencies inconsistency.\n", pts_d, ts_us_d, ff_d);
    } else {
        s->current_frame_ts_us += pts_d;
    }
    s->pts_last = pts_cur;
    s->ts_last_us = ts_us;

    ss = s->dtime_start_s;
    ff = s->current_frame_raw + s->current_frame_diff;
    hh = ss/3600;
    ss = ss-(hh*3600);
    mm = ss/60;
    ss = ss-(mm*60);

    err = av_timecode_init_from_components(&tcr, s->rate, AV_TIMECODE_FLAG_24HOURSMAX, hh, mm, ss, ff, ctx);
    if (0 == err) {
        err = av_timecode_init_from_components(&tcr_raw, s->rate, AV_TIMECODE_FLAG_24HOURSMAX, hh, mm, ss, s->current_frame_raw, ctx);
    }

    {
        // Generate UDU SEI and according metadata for the TimeCode
        /**
         * "TC" - "HH:MM:SS:FF",
         * "TC_RAW" - "HH:MM:SS:FF",
         * "TC_TS" - "YYYY-MM-DDTHH:MM:SS.sssZ",
         * "TS" - "YYYY-MM-DDTHH:MM:SS.sssZ",
         */
        char udu_tc_str[AV_TIMECODE_STR_SIZE];
        const char * udu_tc_str_ptr = NULL;
        char udu_tc_raw_str[AV_TIMECODE_STR_SIZE];
        const char * udu_tc_raw_str_ptr = NULL;
        char udu_tc_ts_str[25];
        const char * udu_tc_ts_str_ptr = NULL;
        char udu_ts_str[25];
        const char * udu_ts_str_ptr = NULL;

        int64_t ts_ms_raw = ts_us_raw/1000;
        time_t ts_s_raw = ts_ms_raw/1000;
        struct tm tm_raw;
        gmtime_r(&ts_s_raw, &tm_raw);

        if (0 == err) {
            if (NULL != (udu_tc_str_ptr = av_timecode_make_string(&tcr, udu_tc_str, 0))) {
                if (av_dict_set(&frame->metadata, "udu_tc", udu_tc_str_ptr, 0) < 0) {
                    av_log(ctx, AV_LOG_ERROR, "'udu_tc' metadata adding error.\n");
                }
            }
        }
        if (0 == err) {
            if (NULL != (udu_tc_raw_str_ptr = av_timecode_make_string(&tcr_raw, udu_tc_raw_str, 0))) {
                if (av_dict_set(&frame->metadata, "udu_tc_raw", udu_tc_raw_str_ptr, 0) < 0) {
                    av_log(ctx, AV_LOG_ERROR, "'udu_tc_raw' metadata adding error.\n");
                }
            }
        }
        if (0 == err) {
            // TODO: Round TimeCode's TimeStamp to the frame
            int64_t ts_ms = s->current_frame_ts_us/1000;
            time_t ts_s = ts_ms/1000;
            struct tm tm;
            gmtime_r(&ts_s, &tm);
            if (0 < snprintf(udu_tc_ts_str, sizeof(udu_tc_ts_str), "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ", tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, (int)(ts_ms%1000ll))) {
                udu_tc_ts_str_ptr = udu_tc_ts_str;
                if (av_dict_set(&frame->metadata, "udu_tc_ts", udu_tc_ts_str_ptr, 0) < 0) {
                    av_log(ctx, AV_LOG_ERROR, "'udu_tc_ts' metadata adding error.\n");
                }
            }
        }
        if (0 < snprintf(udu_ts_str, sizeof(udu_ts_str), "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ", tm_raw.tm_year+1900, tm_raw.tm_mon+1, tm_raw.tm_mday, tm_raw.tm_hour, tm_raw.tm_min, tm_raw.tm_sec, (int)(ts_ms_raw%1000ll))) {
            udu_ts_str_ptr = udu_ts_str;
            if (av_dict_set(&frame->metadata, "timestamp_ms", udu_ts_str_ptr, 0) < 0) {
                av_log(ctx, AV_LOG_ERROR, "'timestamp_ms' metadata adding error.\n");
            }
            if (av_dict_set(&frame->metadata, "udu_ts", udu_ts_str_ptr, 0) < 0) {
                av_log(ctx, AV_LOG_ERROR, "'udu_ts' metadata adding error.\n");
            }
        }
        if (UDU_SEI_JSON == s->udu_sei) {
            /**
             * {
             *   "TC":"HH:MM:SS:FF",
             *   "TC_RAW":"HH:MM:SS:FF",
             *   "TC_TS":"YYYY-MM-DDTHH:MM:SS.sssZ",
             *   "TS":"YYYY-MM-DDTHH:MM:SS.sssZ",
             * }
             */
            // TODO: Update previous UDU_SEI_JSON's AV_FRAME_DATA_SEI_UNREGISTERED frame side data
            // TODO: Use dynamic JSON builder
            const char * template = "{\"TC\":\"%s\",\"TC_RAW\":\"%s\",\"TC_TS\":\"%s\",\"TS\":\"%s\"}";
#define UDU_SEI_JSON_BUF_SIZE sizeof("{\"TC\":\"HH:MM:SS:FF\",\"TC_RAW\":\"HH:MM:SS:FF\",\"TC_TS\":\"YYYY-MM-DDTHH:MM:SS.sssZ\",\"TS\":\"YYYY-MM-DDTHH:MM:SS.sssZ\"}")
            char buf[AV_UUID_LEN + UDU_SEI_JSON_BUF_SIZE];
            int sd_size;
            memcpy(buf, s->udu_sei_uuid, AV_UUID_LEN);
            if (0 < (sd_size = snprintf(buf+AV_UUID_LEN, UDU_SEI_JSON_BUF_SIZE, template, udu_tc_str_ptr, udu_tc_raw_str_ptr, udu_tc_ts_str_ptr, udu_ts_str_ptr))) {
                AVFrameSideData *sd = NULL;
                sd_size+=AV_UUID_LEN;
                sd = av_frame_new_side_data(frame, AV_FRAME_DATA_SEI_UNREGISTERED, sd_size);
                if (NULL != sd) {
                    memcpy(sd->data, buf, sd_size);
                } else {
                    av_log(ctx, AV_LOG_ERROR, "UDU SEI JSON timecode side data adding error.\n");
                }
            } else {
                av_log(ctx, AV_LOG_ERROR, "UDU SEI JSON timecode filling error.\n");
            }
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
    .uninit        = uninit,
};
