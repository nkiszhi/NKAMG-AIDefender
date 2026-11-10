<template>
  <section class="detection-stats">
    <div class="ds-heading">
      <div class="eyebrow">DETECTION OVERVIEW</div>
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
          <div class="ds-panel-title"><h3>检测结果分布</h3><span>已归类 {{ number(snapshot.classified_total) }} / {{ number(snapshot.received_total) }} 次</span></div>
          <div class="ds-distribution">
            <div class="ds-ring" :style="ringStyle" role="img" :aria-label="distributionLabel"><div><strong>{{ number(snapshot.classified_total) }}</strong><span>已归类结果</span></div></div>
            <div class="ds-legend">
              <div v-for="row in outcomes" :key="row.key"><i :style="{ background: row.color }"></i><span>{{ row.label }}</span><b>{{ number(row.count) }}</b><small>{{ percent(row.count) }}</small></div>
            </div>
          </div>
        </article>
        <article class="ds-panel">
          <div class="ds-panel-title"><h3>检测处理概况</h3><span>持久化记录</span></div>
          <div class="ds-route"><span>文件上传检测</span><b>{{ number(snapshot.upload_total) }}</b></div>
          <div class="ds-route"><span>样本库命中</span><b>{{ number(snapshot.database_total) }}</b></div>
          <div class="ds-route"><span>模型检测完成</span><b>{{ number(snapshot.model_total) }}</b></div>
          <div class="ds-route"><span>独立样本 <small>SHA256 去重</small></span><b>{{ number(snapshot.unique_completed_samples) }}</b></div>
          <div class="ds-query"><span>指纹查询 · SHA256 / TLSH / SSDeep</span><strong>{{ number(snapshot.query_total) }} <small>次</small></strong><p>命中 {{ number(snapshot.query_hit_total) }} · 未命中 {{ number(snapshot.query_miss_total) }} · 失败 {{ number(snapshot.query_failed_total) }}<template v-if="snapshot.query_pending_total"> · 查询中 {{ number(snapshot.query_pending_total) }}</template></p></div>
        </article>
      </div>
      <div class="ds-footer"><span>统计起点 {{ date(snapshot.started_at) }} · 更新于 {{ date(snapshot.updated_at, true) }}（北京时间）</span></div>
    </template>
    <div v-else-if="!error" class="ds-error">{{ busy ? '正在读取检测记录…' : '尚无检测统计' }}</div>
  </section>
</template>

<script setup>
import { computed, onMounted, onUnmounted, ref } from 'vue'

const props = defineProps({ api: { type: Object, required: true }, baseUrl: { type: String, required: true } })
const snapshot = ref({ available: false })
const busy = ref(false)
const error = ref('')
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
  { key: 'received_total', label: '累计检测', note: '文件检测与指纹查询次数', color: 'blue' },
  { key: 'malicious_total', label: '判定恶意', note: 'SHA256 命中或模型恶意判定', color: 'red' },
  { key: 'not_detected_total', label: '未检出恶意', note: '未匹配指纹或未检出恶意', color: 'green' },
  { key: 'suspicious_total', label: '判定可疑', note: 'TLSH / SSDeep 命中', color: 'amber' }
]
const outcomes = computed(() => [
  { key: 'malicious_total', label: '判定恶意', color: '#ff7185' },
  { key: 'not_detected_total', label: '未检出恶意', color: '#43d6b0' },
  { key: 'suspicious_total', label: '判定可疑', color: '#eabd72' }
].map(row => ({ ...row, count: Number(snapshot.value[row.key] || 0) })))
const percent = count => snapshot.value.classified_total > 0 ? `${(count / snapshot.value.classified_total * 100).toFixed(1)}%` : '—'
const distributionLabel = computed(() => outcomes.value.map(row => `${row.label} ${number(row.count)} 次`).join('，'))
const ringStyle = computed(() => {
  let offset = 0
  if (!snapshot.value.classified_total) return { background: '#2c3855' }
  const stops = outcomes.value.map(row => {
    const start = offset
    offset += row.count / snapshot.value.classified_total * 100
    return `${row.color} ${start}% ${offset}%`
  })
  return { background: `conic-gradient(${stops.join(',')})` }
})
async function refresh() {
  if (busy.value) return
  busy.value = true
  try {
    const { data } = await props.api.get(`${props.baseUrl}/detection-stats`, { timeout: 10000 })
    if (data.available !== true) throw new Error('unavailable')
    snapshot.value = data
    error.value = ''
  } catch {
    error.value = '暂时无法刷新，当前保留已显示的统计。'
  } finally { busy.value = false }
}
onMounted(() => { void refresh(); timer = window.setInterval(refresh, 15000) })
onUnmounted(() => window.clearInterval(timer))
defineExpose({ refresh })
</script>

<style scoped>
.detection-stats { padding: 10px 0 20px; }
.ds-heading { display: flex; justify-content: space-between; align-items: center; gap: 16px; margin: 8px 0 24px; }
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
.ds-footer { display: flex; align-items: center; justify-content: space-between; gap: 14px; border-top: 1px solid #2b3b58; padding-top: 13px; color: #8296b9; font-size: 11px; }.ds-footer button { flex-shrink: 0; }
.ds-error { margin: 10px 0; color: #eac88c; font-size: 12px; }
@media (max-width: 1000px) { .ds-charts { grid-template-columns: 1fr; }.ds-distribution { justify-content: center; }.ds-legend { max-width: 290px; }.ds-kpi { padding: 17px; } }
@media (max-width: 600px) { .ds-kpis { grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; }.ds-heading h2 { font-size: 19px; }.ds-distribution { flex-direction: column; gap: 12px; }.ds-legend { width: 100%; }.ds-footer { align-items: flex-start; flex-direction: column; }.ds-ring { width: 170px; height: 170px; } }
</style>
