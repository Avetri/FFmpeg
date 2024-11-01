#include <stdlib.h>

#include "libavutil/common.h"
#include "libavutil/opt.h"

#include "bsf.h"
#include "bsf_internal.h"
#include "cbs.h"


typedef struct FilterSubunitContext {
    const AVClass *class;

    CodedBitstreamContext *cbc;
    CodedBitstreamFragment fragment;

    int type;
    int subtype_offset;
    int subtype_size;
    int subtype;
} FilterSubunitContext;

static uint32_t filter_subunit_read_subtype(uint8_t *buf, int len_byte, int offset_bit, int size_bit) {
    uint32_t res=0, bit=0;
    int last_bit = offset_bit+size_bit-1;
    if (NULL == buf || len_byte < 1 || offset_bit < 0 || size_bit < 1 || size_bit > 31 || (last_bit+1) > (len_byte*8)) {
        return UINT32_MAX;
    }
    for (;offset_bit<=last_bit;offset_bit++) {
        int byte_idx = offset_bit/8;
        int bit_idx = offset_bit%8;
        bit = buf[byte_idx];
        bit >>= (7-bit_idx);
        bit &= 0x01;
        res <<= 1;
        res |= bit;
    }
    return res;
}

static int filter_subunit_filter(AVBSFContext *bsf, AVPacket *pkt)
{
    FilterSubunitContext      *ctx = bsf->priv_data;
    CodedBitstreamFragment *frag = &ctx->fragment;
    int err, i;

    err = ff_bsf_get_packet_ref(bsf, pkt);
    if (err < 0)
        return err;

    err = ff_cbs_read_packet(ctx->cbc, frag, pkt);
    if (err < 0) {
        av_log(bsf, AV_LOG_ERROR, "Failed to read packet.\n");
        goto fail;
    }


    for (i = frag->nb_units - 1; i >= 0; i--) {
        if (frag->units[i].type == ctx->type && NULL != frag->units[i].data) {
            uint32_t value = filter_subunit_read_subtype(frag->units[i].data, frag->units[i].data_size, 8+ctx->subtype_offset, ctx->subtype_size);
            if (value == (uint32_t)(ctx->subtype)) {
                ff_cbs_delete_unit(frag, i);
            }
        }
    }

    if (frag->nb_units == 0) {
        // Don't return packets with nothing in them.
        err = AVERROR(EAGAIN);
        goto fail;
    }

    err = ff_cbs_write_packet(ctx->cbc, pkt, frag);
    if (err < 0) {
        av_log(bsf, AV_LOG_ERROR, "Failed to write packet.\n");
        goto fail;
    }

fail:
    if (err < 0)
        av_packet_unref(pkt);
    ff_cbs_fragment_reset(frag);

    return err;
}

static int filter_subunit_init(AVBSFContext *bsf)
{
    FilterSubunitContext *ctx = bsf->priv_data;
    int err;


    if (ctx->type < 0 || ctx->subtype_offset < 0 || ctx->subtype_size < 1 || ctx->subtype_size > 31 || ctx->subtype < 0 ) {
        av_log(bsf, AV_LOG_ERROR, "Wrong filter parameters.\n");
        return AVERROR(EINVAL);
    }

    err = ff_cbs_init(&ctx->cbc, bsf->par_in->codec_id, bsf);
    if (err < 0)
        return err;

    if (bsf->par_in->extradata) {
        CodedBitstreamFragment *frag = &ctx->fragment;

        err = ff_cbs_read_extradata(ctx->cbc, frag, bsf->par_in);
        if (err < 0) {
            av_log(bsf, AV_LOG_ERROR, "Failed to read extradata.\n");
        } else {
            err = ff_cbs_write_extradata(ctx->cbc, bsf->par_out, frag);
            if (err < 0)
                av_log(bsf, AV_LOG_ERROR, "Failed to write extradata.\n");
        }

        ff_cbs_fragment_reset(frag);
    }

    return err;
}

static void filter_subunit_close(AVBSFContext *bsf)
{
    FilterSubunitContext *ctx = bsf->priv_data;

    ff_cbs_fragment_free(&ctx->fragment);
    ff_cbs_close(&ctx->cbc);
}

#define OFFSET(x) offsetof(FilterSubunitContext, x)
#define FLAGS (AV_OPT_FLAG_VIDEO_PARAM|AV_OPT_FLAG_BSF_PARAM)
static const AVOption filter_subunit_options[] = {
    { "type", "Remove a subtype of this type", OFFSET(type), AV_OPT_TYPE_INT, { .i64 = -1 }, -1, INT_MAX, FLAGS},
    { "subtype_offset", "Position where to search subtype, bit offset", OFFSET(subtype_offset), AV_OPT_TYPE_INT, { .i64 = 0 }, 0, INT_MAX, FLAGS},
    { "subtype_size", "Size of the subtype", OFFSET(subtype_size), AV_OPT_TYPE_INT, { .i64 = 8 }, 1, INT_MAX, FLAGS},
    { "subtype", "Subtype value", OFFSET(subtype), AV_OPT_TYPE_INT, { .i64 = -1 }, -1, INT_MAX, FLAGS},

    { NULL }
};

static const AVClass filter_subunit_class = {
    .class_name = "filter_subunit",
    .item_name  = av_default_item_name,
    .option     = filter_subunit_options,
    .version    = LIBAVUTIL_VERSION_INT,
};

const FFBitStreamFilter ff_filter_subunit_bsf = {
    .p.name         = "filter_subunit",
    .p.codec_ids    = ff_cbs_all_codec_ids,
    .p.priv_class   = &filter_subunit_class,
    .priv_data_size = sizeof(FilterSubunitContext),
    .init           = &filter_subunit_init,
    .close          = &filter_subunit_close,
    .filter         = &filter_subunit_filter,
};
