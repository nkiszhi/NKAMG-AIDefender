<template>
  <section class="detection-stats">
    <div class="ds-heading">
      <div><div class="eyebrow">DETECTION OVERVIEW</div><h2>每一次检测，都有迹可循</h2><p>汇总平台文件检测与样本检索记录</p></div>
      <button class="ds-refresh" :disabled="busy" @click="refresh">{{ busy ? '更新中…' : '刷新统计' }}</button>
    </div>
    <div v-if="error" class="ds-error" role="status">{{ error }}</div>
    <template v-if="snapshot.available">
      <div class="ds-kpis">
        <article v-for="item in cards" :key="item.key" :class="['ds-kpi', item.color]">
          <span>{{ item.label }}</span><strong>{{ number(snapshot[item.key]) }}</strong><small>{{ item.note }}</small>
        </article>
      </div>
      <div class="ds-charts">
        <article class="ds-panel">
          <div class="ds-panel-title"><h3>检测结果分布</h3><span>按上传请求计次</span></div>
          <div class="ds-distribution">
            <div class="ds-ring" :style="ringStyle" role="img" :aria-label="distributionLabel"><div><strong>{{ number(snapshot.received_total) }}</strong><span>累计检测</span></div></div>
            <div class="ds-legend">
              <div v-for="row in outcomes" :key="row.key"><i :style="{ background: row.color }"></i><span>{{ row.label }}</span><b>{{ number(row.count) }}</b><small>{{ percent(row.count) }}</small></div>
            </div>
          </div>
        </article>
        <article class="ds-panel">
          <div class="ds-panel-title"><h3>检测处理概况</h3><span>持久化记录</span></div>
          <div class="ds-route"><span>样本库命中</span><b>{{ number(snapshot.database_total) }}</b></div>
          <div class="ds-route"><span>模型检测完成</span><b>{{ number(snapshot.model_total) }}</b></div>
          <div class="ds-route"><span>独立检测样本 <small>SHA256 去重</small></span><b>{{ number(snapshot.unique_completed_samples) }}</b></div>
          <div class="ds-query"><span>SHA256 查询</span><strong>{{ number(snapshot.query_total) }} <small>次</small></strong><p>命中 {{ number(snapshot.query_hit_total) }} · 未命中 {{ number(snapshot.query_miss_total) }} · 失败 {{ number(snapshot.query_failed_total) }}</p></div>
        </article>
      </div>
      <p class="ds-note">已完成 {{ number(snapshot.completed_total) }} 次；未明确判定 {{ number(snapshot.inconclusive_total) }} 次，失败 {{ number(snapshot.failed_total) }} 次，取消 {{ number(snapshot.cancelled_total) }} 次，处理中 {{ number(snapshot.pending_total) }} 次。结构不一致指未通过 PE 结构校验；查询未命中不代表安全。模型结果不等同于人工复核结论。</p>
      <div class="ds-footer"><span>统计起点 {{ date(snapshot.started_at) }} · 更新于 {{ date(snapshot.updated_at, true) }}（北京时间）</span><button class="ds-refresh" @click="showParagraph = !showParagraph">{{ showParagraph ? '收起正文' : '生成正文段落' }}</button></div>
      <div v-if="showParagraph" class="ds-paragraph"><p>{{ paragraph }}</p><button class="ds-refresh" @click="copyParagraph">{{ copied ? '已复制' : '复制正文' }}</button></div>
    </template>
    <div v-else-if="!error" class="ds-error">{{ busy ? '正在读取检测记录…' : '尚无检测统计' }}</div>
  </section>
</template>

<script setup>
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { detectionPreview } from './detectionPreview'

const props = defineProps({ api: { type: Object, required: true }, baseUrl: { type: String, required: true }, preview: Boolean })
const snapshot = ref(props.preview ? { ...detectionPreview } : { available: false })
const busy = ref(false)
const error = ref('')
const showParagraph = ref(false)
const copied = ref(false)
let timer
const number = value => Number(value || 0).toLocaleString('zh-CN')
const date = (value, withTime = false) => {
  if (!value) return '—'
  const parsed = new Date(value)
  return Number.isNaN(parsed.getTime()) ? '—' : new Intl.DateTimeFormat('zh-CN', {
    timeZone: 'Asia/Shanghai', year: 'numeric', month: '2-digit', day: '2-digit',
    ...(withTime ? { hour: '2-digit', minute: '2-digit' } : {})
  }).format(parsed)
}
const cards = [
  { key: 'received_total', label: '累计检测', note: '已接收的文件检测请求', color: 'blue' },
  { key: 'malicious_total', label: '判定恶意', note: '样本库命中或模型恶意判定', color: 'red' },
  { key: 'benign_total', label: '未检出恶意', note: '模型返回未检出恶意', color: 'green' },
  { key: 'unsupported_total', label: '结构不一致', note: '未通过 PE 结构校验', color: 'amber' }
]
const outcomes = computed(() => [
  { key: 'malicious_total', label: '判定恶意', color: '#ff7185' },
  { key: 'benign_total', label: '未检出恶意', color: '#43d6b0' },
  { key: 'unsupported_total', label: '结构不一致', color: '#eabd72' },
  { key: 'other', label: '其他 / 处理中', color: '#8294b7' }
].map(row => ({ ...row, count: row.key === 'other'
  ? Math.max(0, snapshot.value.received_total - snapshot.value.malicious_total - snapshot.value.benign_total - snapshot.value.unsupported_total)
  : Number(snapshot.value[row.key] || 0) })))
const percent = count => snapshot.value.received_total > 0 ? `${(count / snapshot.value.received_total * 100).toFixed(1)}%` : '—'
const distributionLabel = computed(() => outcomes.value.map(row => `${row.label} ${number(row.count)} 次`).join('，'))
const ringStyle = computed(() => {
  let offset = 0
  if (!snapshot.value.received_total) return { background: '#2c3855' }
  const stops = outcomes.value.map(row => {
    const start = offset
    offset += row.count / snapshot.value.received_total * 100
    return `${row.color} ${start}% ${offset}%`
  })
  return { background: `conic-gradient(${stops.join(',')})` }
})
const paragraph = computed(() => {
  const s = snapshot.value
  const prefix = props.preview ? '预览稿：' : ''
  return `${prefix}自 ${date(s.started_at)} 至 ${date(s.updated_at)}，NKAMG-AIDefender 平台累计接收文件检测请求 ${number(s.received_total)} 次，完成检测 ${number(s.completed_total)} 次；其中判定恶意 ${number(s.malicious_total)} 次、未检出恶意 ${number(s.benign_total)} 次、未明确判定 ${number(s.inconclusive_total)} 次，另有 ${number(s.unsupported_total)} 次上传未通过 PE 结构校验。已完成检测覆盖 ${number(s.unique_completed_samples)} 个独立样本（按 SHA256 去重）。另提供 SHA256 查询 ${number(s.query_total)} 次，其中命中恶意样本库 ${number(s.query_hit_total)} 次。检测次数按请求计次，不等同于独立样本数量；模型判定不作为检测准确率。`
})

async function refresh() {
  if (busy.value) return
  busy.value = true
  try {
    const { data } = await props.api.get(`${props.baseUrl}/detection-stats`, { timeout: 10000 })
    if (data.available !== true) throw new Error('unavailable')
    if (props.preview) {
      // Add real activity to the screenshot baseline in memory only.
      const display = { ...detectionPreview, updated_at: data.updated_at }
      for (const [key, value] of Object.entries(detectionPreview)) {
        if (typeof value === 'number') display[key] = value + Number(data[key] || 0)
      }
      snapshot.value = display
    } else snapshot.value = data
    error.value = ''
  } catch {
    if (!props.preview) error.value = snapshot.value.available ? '暂时无法刷新，当前显示上次读取的记录。' : '检测统计暂不可用，请确认后端已更新。'
  } finally { busy.value = false }
}
async function copyParagraph() {
  try { await navigator.clipboard.writeText(paragraph.value); copied.value = true }
  catch { error.value = '复制不可用，请直接选择正文段落复制。' }
}
onMounted(() => { void refresh(); timer = window.setInterval(refresh, 15000) })
onUnmounted(() => window.clearInterval(timer))
defineExpose({ refresh })
</script>

<style scoped>
.detection-stats { padding: 10px 0 20px; }
.ds-heading { display: flex; justify-content: space-between; align-items: center; gap: 16px; margin: 8px 0 24px; }
.ds-heading h2 { margin: 8px 0; font-size: 23px; font-weight: 650; color: #edf2ff; }
.ds-heading p { margin: 0; color: var(--muted); font-size: 12px; }
.ds-refresh { border: 1px solid #41557f; border-radius: 7px; background: #202d48; color: #b8cbf4; padding: 7px 13px; cursor: pointer; font-size: 12px; }
.ds-refresh:disabled { opacity: .6; cursor: wait; }
.ds-kpis { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 15px; margin-bottom: 20px; }
.ds-kpi { padding: 21px 22px; border: 1px solid #334361; border-radius: 12px; background: linear-gradient(125deg, #23314c, #19253d); box-shadow: inset 0 2px #789bff; }
.ds-kpi > span { font-size: 13px; color: #c4d1e9; }
.ds-kpi strong { display: block; margin: 10px 0 9px; font-size: clamp(25px, 3vw, 36px); line-height: 1.2; color: #a3bdff; font-variant-numeric: tabular-nums; letter-spacing: -.025em; }
.ds-kpi small { color: #8fa1bf; font-size: 11px; }
.ds-kpi.red { box-shadow: inset 0 2px #ff7185; }.ds-kpi.red strong { color: #ff8b9b; }
.ds-kpi.green { box-shadow: inset 0 2px #43d6b0; }.ds-kpi.green strong { color: #65dfbd; }
.ds-kpi.amber { box-shadow: inset 0 2px #eabd72; }.ds-kpi.amber strong { color: #eac88c; }
.ds-charts { display: grid; grid-template-columns: 1.25fr 1fr; gap: 18px; }
.ds-panel { border: 1px solid #334361; border-radius: 12px; padding: 22px; background: #17233a; }
.ds-panel-title { display: flex; justify-content: space-between; align-items: center; gap: 12px; margin-bottom: 22px; }
.ds-panel-title h3 { font-size: 14px; margin: 0; color: #dce7ff; }.ds-panel-title > span { color: #8193b2; font-size: 11px; }
.ds-distribution { display: flex; align-items: center; gap: 24px; padding: 8px 0 16px; }
.ds-ring { width: 190px; height: 190px; border-radius: 50%; padding: 19px; flex: 0 0 auto; transform: rotate(-.001deg); }
.ds-ring > div { width: 100%; height: 100%; border-radius: 50%; background: #17233a; display: flex; align-items: center; justify-content: center; flex-direction: column; }
.ds-ring strong { font-size: 29px; font-variant-numeric: tabular-nums; color: #edf3ff; }.ds-ring span { margin-top: 5px; color: #8da0c0; font-size: 11px; }
.ds-legend { flex: 1; min-width: 0; }.ds-legend > div { display: grid; grid-template-columns: 8px 1fr auto; align-items: center; gap: 10px; margin: 13px 0; }
.ds-legend i { width: 7px; height: 7px; border-radius: 50%; }.ds-legend span { color: #b5c4df; font-size: 12px; }.ds-legend b { font-size: 14px; font-weight: 600; font-variant-numeric: tabular-nums; }.ds-legend small { grid-column: 3; margin-top: -8px; color: #8396b8; text-align: right; font-size: 10px; }
.ds-route { display: flex; justify-content: space-between; padding: 9px 0; border-bottom: 1px solid #293953; font-size: 12px; color: #a8bad9; }.ds-route b { color: #dbe7ff; font-size: 15px; font-variant-numeric: tabular-nums; }.ds-route small { color: #7489ac; font-size: 10px; margin-left: 6px; }
.ds-query { margin-top: 17px; padding: 11px 15px; border-radius: 7px; background: #202e48; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; color: #b4c7eb; font-size: 12px; }.ds-query strong { font-size: 20px; }.ds-query small { font-size: 11px; font-weight: 400; }.ds-query p { flex-basis: 100%; margin: 5px 0 0; color: #8ca1c4; font-size: 11px; }
.ds-note { margin: 17px 0 12px; font-size: 11px; line-height: 1.9; color: #91a3c2; }
.ds-footer { display: flex; align-items: center; justify-content: space-between; gap: 14px; border-top: 1px solid #2b3b58; padding-top: 13px; color: #8296b9; font-size: 11px; }.ds-footer button { flex-shrink: 0; }
.ds-error { margin: 10px 0; color: #eac88c; font-size: 12px; }.ds-paragraph { margin-top: 15px; background: #121e33; padding: 16px; border-radius: 8px; color: #bacbe5; font-size: 12px; line-height: 1.9; }
@media (max-width: 1000px) { .ds-charts { grid-template-columns: 1fr; }.ds-distribution { justify-content: center; }.ds-legend { max-width: 290px; }.ds-kpi { padding: 17px; } }
@media (max-width: 600px) { .ds-kpis { grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; }.ds-heading h2 { font-size: 19px; }.ds-distribution { flex-direction: column; gap: 12px; }.ds-legend { width: 100%; }.ds-footer { align-items: flex-start; flex-direction: column; }.ds-ring { width: 170px; height: 170px; } }
</style>
