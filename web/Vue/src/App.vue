<template>
  <main class="page-shell">
    <section class="header">
      <div class="brand-lockup">
        <div class="brand-mark" aria-hidden="true"><img src="/nkamg-logo.png" alt="NKAMG-AIDefender" /></div>
        <div>
          <div class="eyebrow">NKAMG · MALWARE INTELLIGENCE</div>
          <h1>NKAMG-AIDefender</h1>
          <p>面向 PE 样本的多模型威胁分析工作台</p>
        </div>
      </div>
      <div class="header-tools">
        <form class="hash-search" @submit.prevent="searchSample">
          <el-icon aria-hidden="true"><Search /></el-icon>
          <input v-model.trim="hashQuery" type="search" maxlength="64" spellcheck="false" placeholder="搜索 SHA256" aria-label="搜索 SHA256" />
          <button type="submit" :disabled="searching || !hashQuery">{{ searching ? '查询中' : '查询' }}</button>
        </form>
        <div class="status-tags">
        <span class="service-status" :class="modelService.ready ? 'is-ready' : modelService.connected ? 'is-warning' : 'is-offline'">
          <i></i>
          {{ checkingModels ? '正在检查模型服务' : modelService.ready ? `模型服务已连接 · ${modelService.model_count} 个模型` : modelService.connected ? '模型服务未就绪' : '模型服务未连接' }}
        </span>
        </div>
      </div>
    </section>

    <section class="workbench">
      <div class="upload-zone" @drop="handleDrop" @dragover.prevent>
        <input ref="fileInput" class="hidden-input" type="file" @change="handleFileChange" />
        <div class="upload-orbit" aria-hidden="true"><el-icon class="upload-icon"><UploadFilled /></el-icon></div>
        <div class="eyebrow">STATIC FILE ANALYSIS</div>
        <div class="upload-title">上传样本，开始安全分析</div>
        <div class="upload-subtitle">支持拖拽或选择文件。系统会先校验 PE 结构，再交给多模型引擎分析。</div>
        <div class="upload-actions">
          <el-button type="primary" :loading="loading" @click="selectFile">选择待检文件</el-button>
          <span>单文件不超过 {{ formatFileSize(maxUploadSize) }} · 检测结束后删除样本</span>
        </div>
        <div v-if="loading" class="upload-progress" role="status"><span class="pulse-dot"></span>{{ detectionMessage }}</div>
      </div>

      <el-collapse v-model="modelsOpen" class="models-collapse">
        <el-collapse-item name="modelCatalog">
          <template #title>
            <div class="collapse-title"><span class="collapse-title-mark">01</span><span>检测引擎 · 33 模型介绍</span><small>模型目录</small></div>
          </template>
          <div class="section-intro">
            <div>
              <div class="eyebrow">MODEL CATALOG</div>
              <h2>33 个模型，分别观察样本的不同特征</h2>
            </div>
            <p>每个模型从不同的字节、结构、图和元数据视角观察样本。向下浏览可以了解它们各自负责的分析方向。</p>
          </div>
          <div class="model-story">
            <article v-for="(item, index) in modelDetails" :key="item.name" class="model-story-card">
              <div class="model-story-index">{{ String(index + 1).padStart(2, '0') }}</div>
              <div class="model-story-body">
                <div class="model-story-meta"><span>{{ item.view || '多视角特征' }}</span><b>{{ item.source || 'CoDefenderC3' }}</b></div>
                <h3>{{ item.name }}</h3>
                <p>{{ modelDescription(item) }}</p>
                <div class="model-story-details">
                  <span><b>特征</b>{{ item.features || '项目特征' }}</span>
                  <span><b>用途</b>{{ item.role || '参与多模型恶意文件判定' }}</span>
                </div>
              </div>
            </article>
          </div>
        </el-collapse-item>
        <el-collapse-item name="sampleLibrary">
          <template #title>
            <div class="collapse-title"><span class="collapse-title-mark">02</span><span>样本库</span><small>样本与域名统计</small></div>
          </template>
          <div class="catalog-divider"><span>DATA INSIGHTS</span></div>
          <div v-if="stats.available" class="stats-dashboard">
            <div class="stats-kpis">
              <div class="kpi-card kpi-danger"><span>恶意样本</span><strong>{{ formatNumber(stats.samples?.malicious_total) }}</strong><small>已收录样本</small></div>
              <div class="kpi-card kpi-safe"><span>良性样本</span><strong>{{ formatNumber(stats.samples?.benign_total) }}</strong><small>对照样本</small></div>
              <div class="kpi-card kpi-blue"><span>恶意域名</span><strong>{{ formatNumber(stats.domains?.total) }}</strong><small>情报记录</small></div>
            </div>
            <div class="charts-grid">
              <article class="chart-card chart-wide">
                <div class="chart-heading"><div><span class="eyebrow">TREND</span><h3>近 12 个月情报增长</h3></div><div class="chart-legend"><span><i class="legend-dot samples"></i>恶意样本</span><span><i class="legend-dot domains"></i>恶意域名</span></div></div>
                <div v-if="monthlyChart.labels.length" class="line-chart-wrap">
                  <svg class="line-chart" viewBox="0 0 720 280" role="img" aria-label="近十二个月情报增长折线图">
                    <g class="chart-grid-lines"><line v-for="y in chartGridY" :key="y" x1="46" :y1="y" x2="700" :y2="y" /></g>
                    <polyline class="chart-line chart-line-samples" :points="monthlyChart.samplePoints" />
                    <polyline class="chart-line chart-line-domains" :points="monthlyChart.domainPoints" />
                    <g v-for="point in monthlyChart.sampleDots" :key="`s-${point.x}`"><circle class="chart-dot chart-dot-samples" :cx="point.x" :cy="point.y" r="4" /><title>{{ point.label }}：{{ formatNumber(point.value) }}</title></g>
                    <g v-for="point in monthlyChart.domainDots" :key="`d-${point.x}`"><circle class="chart-dot chart-dot-domains" :cx="point.x" :cy="point.y" r="4" /><title>{{ point.label }}：{{ formatNumber(point.value) }}</title></g>
                    <text v-for="point in monthlyChart.sampleDots" :key="`l-${point.x}`" class="chart-axis-label" :x="point.x" y="266" text-anchor="middle">{{ point.label.slice(5) }}</text>
                  </svg>
                </div>
                <div v-else class="chart-empty">暂无月度数据</div>
              </article>
              <article class="chart-card chart-donut-card">
                <div class="chart-heading"><div><span class="eyebrow">COLLECTION MIX</span><h3>样本库构成</h3></div></div>
                <div class="donut-layout"><div class="donut-chart" :style="sampleDonutStyle"><div><strong>{{ formatNumber(sampleTotal) }}</strong><span>样本总量</span></div></div><div class="donut-legend"><span><i class="legend-dot malicious"></i>恶意样本 <b>{{ formatNumber(stats.samples?.malicious_total) }}</b></span><span><i class="legend-dot benign"></i>良性样本 <b>{{ formatNumber(stats.samples?.benign_total) }}</b></span></div></div>
              </article>
            </div>
            <div class="top-lists-grid">
              <article v-for="field in sampleTopFields" :key="field.key" class="top-list-card"><div class="chart-heading"><div><span class="eyebrow">样本分类</span><h3>{{ field.label }}分布</h3></div></div><div v-if="stats.samples?.[field.key]?.length" class="bar-list"><div v-for="item in stats.samples[field.key].slice(0, 5)" :key="item.name" class="bar-row"><div><span>{{ item.name }}</span><b>{{ formatNumber(item.count) }}</b></div><i><em :style="{ width: `${topBarWidth(stats.samples[field.key], item.count)}%` }"></em></i></div></div><div v-else class="chart-empty compact">暂无数据</div></article>
              <article v-for="field in domainTopFields" :key="`domain-${field.key}`" class="top-list-card"><div class="chart-heading"><div><span class="eyebrow">域名情报</span><h3>域名{{ field.label }}分布</h3></div></div><div v-if="stats.domains?.[field.key]?.length" class="bar-list"><div v-for="item in stats.domains[field.key].slice(0, 5)" :key="item.name" class="bar-row"><div><span>{{ item.name }}</span><b>{{ formatNumber(item.count) }}</b></div><i><em :style="{ width: `${topBarWidth(stats.domains[field.key], item.count)}%` }"></em></i></div></div><div v-else class="chart-empty compact">暂无数据</div></article>
            </div>
            <p class="muted-text stats-updated">数据更新时间：{{ stats.updated_at || '-' }}</p>
          </div>
          <div v-else class="stats-unavailable"><span class="pulse-dot"></span>{{ stats.reason || '统计数据暂不可用' }}</div>
        </el-collapse-item>
      </el-collapse>
    </section>

    <section v-if="uploadResult" ref="resultSection" class="results">
      <div class="result-head">
        <div>
          <button class="back-button" type="button" @click="resetResult">返回工作台</button>
          <h2>检测报告如下</h2>
          <div class="tags">
            <el-tag :type="uploadResult.is_pe ? 'success' : 'warning'">
              {{ uploadResult.is_pe ? 'PE结构：有效' : '检测失败：非 PE 文件' }}
            </el-tag>
            <el-tag v-if="uploadResult.database_hit" type="danger">恶意：命中 NKAMG 样本库</el-tag>
            <el-tag v-else-if="uploadResult.is_pe && uploadResult.detection_mode === 'models'" type="info">样本库：未命中</el-tag>
            <el-tag v-if="ensembleResult" :type="ensembleResult.result === '恶意' ? 'danger' : ensembleResult.result === '安全' ? 'success' : 'warning'">
              多模型结果：{{ ensembleResult.result }}
            </el-tag>
            <el-tag v-if="ensembleResult?.virus_name" type="warning">
              病毒名称：{{ ensembleResult.virus_name }}
            </el-tag>
          </div>
        </div>
        <el-radio-group v-model="showSection">
          <el-radio-button v-for="item in sectionOptions" :key="item.value" :label="item.value">
            {{ item.label }}
          </el-radio-button>
        </el-radio-group>
      </div>

      <div v-show="showSection === 'fileInfo'" class="panel">
        <div v-if="!uploadResult.is_pe" class="detection-warning">
          <strong>检测状态：检测失败</strong>
          <div>文件类型：非 PE 文件</div>
          <div>原因：{{ uploadResult.reason || '不是有效PE样本' }}</div>
          <div>文件头：<span class="mono">{{ uploadResult.file_header || '-' }}</span></div>
        </div>
        <div v-else-if="uploadResult.database_hit" class="database-hit">
          <strong>已命中样本库，跳过 33 模型检测</strong>
          <span v-if="uploadResult.sample_record?.source_db">来源：{{ uploadResult.sample_record.source_db }}.{{ uploadResult.sample_record.source_table }}</span>
        </div>
        <template v-if="uploadResult.database_hit && uploadResult.sample_record">
          <h3 class="subhead">样本基础信息</h3>
          <el-descriptions :column="2" border class="sample-description">
            <el-descriptions-item v-for="(value, key) in sampleBaseFields" :key="key" :label="key">{{ key === '文件大小' ? formatFileSize(value) : value }}</el-descriptions-item>
          </el-descriptions>
          <h3 class="subhead">样本标签</h3>
          <el-descriptions :column="2" border>
            <el-descriptions-item v-for="(value, key) in uploadResult.sample_record.labels" :key="key" :label="key">{{ value || '-' }}</el-descriptions-item>
          </el-descriptions>
        </template>
        <el-descriptions :column="1" border>
          <el-descriptions-item v-if="!uploadResult.database_hit" label="文件名">{{ uploadResult.filename || '-' }}</el-descriptions-item>
          <el-descriptions-item v-if="!uploadResult.database_hit" label="SHA256">
            <span class="mono break-text">{{ uploadResult.sha256 || '-' }}</span>
          </el-descriptions-item>
          <el-descriptions-item v-if="!uploadResult.database_hit" label="MD5">
            <span class="mono break-text">{{ uploadResult.md5 || uploadResult.query_result?.MD5 || '-' }}</span>
          </el-descriptions-item>
          <el-descriptions-item v-if="!uploadResult.database_hit" label="文件大小">{{ formatFileSize(uploadResult.file_size) }}</el-descriptions-item>
          <el-descriptions-item v-if="!uploadResult.database_hit" label="文件类型">{{ uploadResult.file_type || '-' }}</el-descriptions-item>
          <el-descriptions-item label="检测时间">{{ uploadResult.detection_time || '-' }}</el-descriptions-item>
        </el-descriptions>

        <h3 v-if="uploadResult.is_pe" class="subhead">PE结构信息</h3>
        <el-descriptions v-if="uploadResult.is_pe" :column="2" border>
          <el-descriptions-item label="PE格式">{{ peInfo.format || '-' }}</el-descriptions-item>
          <el-descriptions-item label="架构">{{ peInfo.architecture || '-' }}</el-descriptions-item>
          <el-descriptions-item label="Machine">{{ peInfo.machine || '-' }}</el-descriptions-item>
          <el-descriptions-item label="子系统">{{ peInfo.subsystem || '-' }}</el-descriptions-item>
          <el-descriptions-item label="入口点">{{ peInfo.entry_point || '-' }}</el-descriptions-item>
          <el-descriptions-item label="镜像基址">{{ peInfo.image_base || '-' }}</el-descriptions-item>
          <el-descriptions-item label="节数量">{{ peInfo.number_of_sections ?? '-' }}</el-descriptions-item>
          <el-descriptions-item label="编译时间">{{ peInfo.compile_time || '-' }}</el-descriptions-item>
          <el-descriptions-item label="SizeOfImage">{{ formatFileSize(peInfo.size_of_image) }}</el-descriptions-item>
          <el-descriptions-item label="SizeOfHeaders">{{ formatFileSize(peInfo.size_of_headers) }}</el-descriptions-item>
        </el-descriptions>

        <h3 v-if="uploadResult.is_pe" class="subhead">节表</h3>
        <el-table v-if="uploadResult.is_pe" :data="peInfo.sections || []" border stripe>
          <el-table-column prop="name" label="名称" min-width="110" />
          <el-table-column prop="virtual_address" label="VirtualAddress" min-width="140" />
          <el-table-column prop="virtual_size" label="VirtualSize" min-width="120" />
          <el-table-column prop="raw_size" label="RawSize" min-width="120" />
          <el-table-column prop="raw_pointer" label="RawPointer" min-width="130" />
          <el-table-column prop="characteristics" label="Characteristics" min-width="150" />
        </el-table>
      </div>

      <div v-show="showSection === 'modelDetection'" class="panel">
        <div v-if="!uploadResult.is_pe" class="detection-warning">本文件不是 PE，未提交 33 模型检测。</div>
        <div v-else-if="uploadResult.database_hit" class="database-hit">已命中 NKAMG 样本库，已跳过 33 模型检测。</div>
        <template v-else>
        <div class="summary-row">
          <el-tag size="large" type="info">{{ uploadResult.partial ? '检测中 · 已返回部分结果' : '检测结束' }} · 共 {{ modelCount }} 个模型</el-tag>
          <el-tag size="large" type="danger">恶意: {{ maliciousCount }}</el-tag>
          <el-tag size="large" type="success">安全: {{ safeCount }}</el-tag>
          <el-tag v-if="incompleteCount" size="large" type="warning">未取得有效结果: {{ incompleteCount }}</el-tag>
        </div>
        <el-table :data="modelRows" border stripe class="model-table">
          <el-table-column type="index" label="序号" width="70" />
          <el-table-column prop="model" label="检测模型" min-width="180" />
          <el-table-column label="恶意概率" min-width="180">
            <template #default="{ row }">
              <span v-if="row.probability === null || row.probability === undefined">—</span>
              <el-progress v-else :percentage="getProbabilityPercent(row.probability)" :color="getProbabilityColor(row.probability)" />
            </template>
          </el-table-column>
          <el-table-column label="结果" width="120">
            <template #default="{ row }">
              <el-tag :type="row.result === '恶意' ? 'danger' : row.result === '安全' ? 'success' : 'info'">
                {{ row.result }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="reason" label="说明" min-width="180">
            <template #default="{ row }">{{ row.reason || row.virus_name || '-' }}</template>
          </el-table-column>
        </el-table>
        </template>
      </div>
    </section>
  </main>
</template>

<script setup>
import axios from 'axios'
import { computed, nextTick, onMounted, onUnmounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { Search, UploadFilled } from '@element-plus/icons-vue'

const apiService = axios.create({ timeout: 600000 })

const showSection = ref('fileInfo')
const modelsOpen = ref(['modelCatalog', 'sampleLibrary'])
const loading = ref(false)
const maxUploadSize = ref(20 * 1024 * 1024)
const detectionMessage = ref('正在检测，可刷新页面继续等待')
const detectionAbort = new AbortController()
const TASK_KEY = 'aidefender_detection_task'
const TASK_PHASE_KEY = 'aidefender_detection_phase'
const uploadResult = ref(null)
const apiBaseUrl = ref('/api-backend')
const modelService = ref({ connected: false, ready: false, model_count: 0 })
const checkingModels = ref(true)
const stats = ref({ available: false, reason: '启动后正在读取统计数据' })
let modelHealthTimer
const fileInput = ref(null)
const resultSection = ref(null)
const hashQuery = ref('')
const searching = ref(false)
const modelNames = ref([
  'MalConv', 'MalConv2', 'ByteTransformer', 'SaxeBerlinDNN', 'EmberDNN',
  'NatarajKNN', 'DrebinSVM', 'DL4MD', 'PEMinerRF', 'DrebinImport',
  'ALOHANet', 'EmberGBDT_Import', 'RaffFeatureNet', 'DrebinString',
  'OpcodeLSTM', 'OpcodeTransformer', 'OpcodeStatNet', 'AsmEmbedNet',
  'MalGraph', 'CFGGAT', 'CFGGCN', 'CFGDGCNN', 'CallGraphGNN',
  'GraphStatNet', 'GrayscaleCNN', 'InceptionV3', 'IMCFN', 'ColorCNN',
  'MarkovCNN', 'EntropyMapCNN', 'HashEmbedNet', 'MetadataNet', 'ResourceNet'
])
const modelDetails = ref(modelNames.value.map(name => ({ name, view: '多视角特征', features: '项目特征', source: 'CoDefenderC3 项目模型实现', role: '参与多模型恶意文件判定', optimization: '参见项目模型资料' })))
const sampleTopFields = [
  { key: 'category', label: '类别' }, { key: 'platform', label: '平台' },
  { key: 'family', label: '家族' }, { key: 'filetype', label: '文件类型' }
]
const domainTopFields = [{ key: 'source', label: '来源' }, { key: 'category', label: '类别' }]
const chartGridY = [52, 100, 148, 196, 244]

const sectionOptions = [
  { label: '基础信息', value: 'fileInfo' },
  { label: '模型检测', value: 'modelDetection' }
]

const peInfo = computed(() => uploadResult.value?.pe_info || {})
const sampleBaseFields = computed(() => ({
  ...(uploadResult.value?.sample_record?.identity || {}),
  ...(uploadResult.value?.sample_record?.hashes || {})
}))

const sampleTotal = computed(() => Number(stats.value.samples?.malicious_total || 0) + Number(stats.value.samples?.benign_total || 0))

const sampleDonutStyle = computed(() => {
  const total = sampleTotal.value
  const maliciousPercent = total > 0 ? (Number(stats.value.samples?.malicious_total || 0) / total) * 100 : 0
  const benignEnd = total > 0 ? 100 : 0
  return { background: `conic-gradient(#ff596d 0% ${maliciousPercent}%, #35c89b ${maliciousPercent}% ${benignEnd}%, #27354b ${benignEnd}% 100%)` }
})

const monthlyChart = computed(() => {
  const sampleRows = stats.value.samples?.monthly || []
  const domainRows = stats.value.domains?.monthly || []
  const sampleMap = new Map(sampleRows.map(item => [item.name, Number(item.count || 0)]))
  const domainMap = new Map(domainRows.map(item => [item.name, Number(item.count || 0)]))
  const labels = [...new Set([...sampleMap.keys(), ...domainMap.keys()])].sort().slice(-12)
  if (!labels.length) return { labels: [], samplePoints: '', domainPoints: '', sampleDots: [], domainDots: [] }
  const sampleMax = Math.max(1, ...labels.map(label => sampleMap.get(label) || 0))
  const domainMax = Math.max(1, ...labels.map(label => domainMap.get(label) || 0))
  const x = index => labels.length === 1 ? 373 : 52 + (index * 642) / (labels.length - 1)
  const dotsFor = (values, max) => values.map((value, index) => ({
    x: x(index), y: 238 - (value / max) * 184, value, label: labels[index]
  }))
  const sampleDots = dotsFor(labels.map(label => sampleMap.get(label) || 0), sampleMax)
  const domainDots = dotsFor(labels.map(label => domainMap.get(label) || 0), domainMax)
  return {
    labels,
    sampleDots,
    domainDots,
    samplePoints: sampleDots.map(point => `${point.x},${point.y}`).join(' '),
    domainPoints: domainDots.map(point => `${point.x},${point.y}`).join(' ')
  }
})

const modelResults = computed(() => {
  const results = uploadResult.value?.exe_result || uploadResult.value?.results || {}
  return Object.fromEntries(Object.entries(results).filter(([model]) => model !== '集成结果' && model !== 'error'))
})

const ensembleResult = computed(() => {
  const results = uploadResult.value?.exe_result || uploadResult.value?.results || {}
  return results['集成结果'] || null
})

const modelRows = computed(() => Object.entries(modelResults.value).map(([model, data]) => ({
  model,
  probability: data.probability,
  result: data.result,
  virus_name: data.virus_name,
  reason: data.reason
})))

const modelCount = computed(() => modelRows.value.length)
const maliciousCount = computed(() => modelRows.value.filter(row => row.result === '恶意').length)
const safeCount = computed(() => modelRows.value.filter(row => row.result === '安全').length)
const incompleteCount = computed(() => modelRows.value.filter(row => !['恶意', '安全'].includes(row.result)).length)

onMounted(async () => {
  window.addEventListener('pagehide', notifyPageLeave)
  loading.value = Boolean(localStorage.getItem(TASK_KEY))
  await loadConfig()
  try {
    const { data } = await apiService.get(`${apiBaseUrl.value}/upload-policy`, { timeout: 5000 })
    if (Number(data.max_upload_size) > 0) maxUploadSize.value = Number(data.max_upload_size)
  } catch { /* Older servers keep the conservative client limit. */ }
  void Promise.allSettled([loadModels(), loadModelHealth(), loadStats()])
  modelHealthTimer = window.setInterval(loadModelHealth, 30000)
  await restoreDetectionTask()
})
onUnmounted(() => {
  notifyPageLeave()
  window.removeEventListener('pagehide', notifyPageLeave)
  detectionAbort.abort()
  window.clearInterval(modelHealthTimer)
})

function notifyPageLeave() {
  const taskId = localStorage.getItem(TASK_KEY)
  if (loading.value && taskId) navigator.sendBeacon(apiBaseUrl.value + '/detect/tasks/' + taskId + '/leave', '')
}

async function loadConfig() {
  try {
    const response = await apiService.get('/config.ini', { responseType: 'text', timeout: 5000 })
    const parsed = parseIni(response.data)
    apiBaseUrl.value = parsed.codefender?.baseUrl || parsed.api?.baseUrl || apiBaseUrl.value
  } catch (error) {
    console.warn('加载配置文件失败:', error.message)
  }
}

async function loadModelHealth() {
  try {
    const response = await apiService.get(`${apiBaseUrl.value}/model-health`, { timeout: 15000 })
    modelService.value = response.data || modelService.value
  } catch (error) {
    modelService.value = { connected: false, ready: false, model_count: 0 }
  } finally {
    checkingModels.value = false
  }
}

async function loadModels() {
  try {
    const response = await apiService.get(`${apiBaseUrl.value}/models`, { timeout: 5000 })
    if (Array.isArray(response.data?.models)) {
      modelNames.value = response.data.models
      modelDetails.value = Array.isArray(response.data?.catalog)
        ? response.data.catalog
        : modelNames.value.map(name => modelDetails.value.find(item => item.name === name) || ({ name, view: '多视角特征', features: '项目特征', source: 'CoDefenderC3 项目模型实现', role: '参与多模型恶意文件判定', optimization: '参见项目模型资料' }))
    }
  } catch (error) {
    console.warn('加载模型清单失败:', error.message)
  }
}

async function loadStats() {
  try {
    const response = await apiService.get(`${apiBaseUrl.value}/stats`, { timeout: 15000 })
    stats.value = response.data || stats.value
  } catch {
    stats.value = { available: false, reason: '统计接口暂不可用' }
  }
}

function parseIni(text) {
  const result = {}
  let section = ''
  for (const line of text.split('\n')) {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith(';')) continue
    if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
      section = trimmed.slice(1, -1)
      result[section] = result[section] || {}
      continue
    }
    const index = trimmed.indexOf('=')
    if (index > -1 && section) {
      result[section][trimmed.slice(0, index).trim()] = trimmed.slice(index + 1).trim()
    }
  }
  return result
}

function resetResult() {
  uploadResult.value = null
  showSection.value = 'fileInfo'
  modelsOpen.value = []
}

async function searchSample() {
  if (!/^[0-9a-f]{64}$/i.test(hashQuery.value)) {
    ElMessage.warning('请输入 64 位 SHA256')
    return
  }
  searching.value = true
  try {
    const response = await apiService.get(`${apiBaseUrl.value}/samples/${hashQuery.value}`, { timeout: 15000 })
    setDetectionResult(response.data)
    ElMessage.success('已找到样本库记录')
  } catch (error) {
    const status = error.response?.status
    ElMessage.error(status === 404 ? '样本库中未找到该 SHA256' : (error.response?.data?.detail || '样本库查询失败'))
  } finally {
    searching.value = false
  }
}

function selectFile() {
  if (!loading.value) fileInput.value?.click()
}

function handleFileChange(event) {
  const file = event.target.files?.[0]
  if (file) uploadFile(file)
  event.target.value = ''
}

function handleDrop(event) {
  event.preventDefault()
  if (loading.value) return
  const files = event.dataTransfer.files
  if (files.length !== 1) {
    ElMessage.error('只支持上传一个文件')
    return
  }
  uploadFile(files[0])
}

async function uploadFile(file) {
  if (loading.value) return
  if (file.size > maxUploadSize.value) {
    ElMessage.warning(`文件超过大小限制：${formatFileSize(maxUploadSize.value)}`)
    return
  }
  resetResult()
  modelsOpen.value = []
  loading.value = true
  const formData = new FormData()
  formData.append('file', file)
  const randomBytes = new Uint8Array(16)
  window.crypto.getRandomValues(randomBytes)
  const requestId = Array.from(randomBytes, byte => byte.toString(16).padStart(2, '0')).join('')
  // Save the request ID before uploading: refreshing after server acceptance
  // but before the POST response arrives can still recover the existing task.
  localStorage.setItem(TASK_KEY, requestId)
  localStorage.setItem(TASK_PHASE_KEY, 'uploading')
  detectionMessage.value = '正在上传样本'
  try {
    const response = await apiService.post(`${apiBaseUrl.value}/detect`, formData, {
      headers: { 'X-Detection-ID': requestId },
      signal: detectionAbort.signal
    })
    if (response.data?.task_id) {
      localStorage.setItem(TASK_KEY, response.data.task_id)
      localStorage.setItem(TASK_PHASE_KEY, 'accepted')
      await pollDetectionTask(response.data.task_id)
    } else {
      clearSavedTask()
      setDetectionResult(response.data)
      ElMessage.success('检测完成')
    }
  } catch (error) {
    if (detectionAbort.signal.aborted) return
    if (!error.response) {
      // A network failure does not prove the server rejected the upload.
      await pollDetectionTask(requestId)
      return
    }
    clearSavedTask()
    ElMessage.error('检测失败: ' + (error.response?.data?.detail || error.message))
  } finally {
    loading.value = false
  }
}

async function restoreDetectionTask() {
  const taskId = localStorage.getItem(TASK_KEY)
  if (taskId) await pollDetectionTask(taskId)
}

function clearSavedTask() {
  localStorage.removeItem(TASK_KEY)
  localStorage.removeItem(TASK_PHASE_KEY)
}

async function pollDetectionTask(taskId) {
  loading.value = true
  let missingCount = 0
  try {
    while (!detectionAbort.signal.aborted) {
      let response
      try {
        response = await apiService.get(`${apiBaseUrl.value}/detect/tasks/${taskId}`, {
          timeout: 15000, signal: detectionAbort.signal
        })
        missingCount = 0
      } catch (error) {
        if (detectionAbort.signal.aborted) return
        if (error.response?.status === 404) {
          const uploading = localStorage.getItem(TASK_PHASE_KEY) === 'uploading'
          if (!uploading || ++missingCount >= 12) {
            clearSavedTask()
            throw new Error(uploading ? '上次上传尚未完成，请重新选择文件' : '检测记录已过期，请重新选择文件')
          }
        } else if (error.response && error.response.status < 500 && error.response.status !== 429) {
          throw error
        }
        detectionMessage.value = '连接暂时中断，正在恢复检测结果…'
        await new Promise(resolve => window.setTimeout(resolve, 3000))
        continue
      }
      const task = response.data || {}
      if (task.status === 'completed') {
        setDetectionResult(task.result || {})
        // Keep the ID until a new upload, so refreshing a completed report
        // also restores it during the server's configured retention period.
        localStorage.setItem(TASK_PHASE_KEY, 'accepted')
        ElMessage.success('检测完成')
        return
      }
      if (task.status === 'failed' || task.status === 'cancelled') {
        clearSavedTask()
        throw new Error(task.error || '检测任务失败')
      }
      localStorage.setItem(TASK_PHASE_KEY, 'accepted')
      if (task.progress?.models) {
        const labels = { waiting: '等待中', running: '正在检测', timeout: '超时', error: '失败', unavailable: '不可用', skipped: '已跳过' }
        const results = Object.fromEntries(task.progress.models.map(item => [item.model, {
          probability: item.status === 'ok' ? item.score : null,
          result: item.status === 'ok' ? (item.prediction === 1 ? '恶意' : '安全') : (labels[item.status] || '等待中'),
          reason: item.reason || ''
        }]))
        const firstProgress = !uploadResult.value
        uploadResult.value = normalizeDetectionResponse({ ...task.progress.file_info, partial: true, exe_result: results })
        if (firstProgress) showSection.value = 'modelDetection'
      }
      detectionMessage.value = task.status === 'queued'
        ? (Number(task.tasks_ahead) > 0 ? `正在排队，前方还有 ${task.tasks_ahead} 个任务` : '任务已接收，即将开始检测')
        : '正在检测，可刷新页面继续等待'
      await new Promise(resolve => window.setTimeout(resolve, 2500))
    }
  } catch (error) {
    if (detectionAbort.signal.aborted) return
    ElMessage.error('检测失败: ' + (error.response?.data?.detail || error.message))
  } finally {
    loading.value = false
  }
}

function setDetectionResult(data) {
  const normalized = normalizeDetectionResponse(data)
  uploadResult.value = normalized
  showSection.value = normalized.is_pe && !normalized.database_hit ? 'modelDetection' : 'fileInfo'
  modelsOpen.value = []
  nextTick(() => resultSection.value?.scrollIntoView({ behavior: 'smooth', block: 'start' }))
}

function topBarWidth(rows, count) {
  const max = Math.max(1, ...(rows || []).map(item => Number(item.count || 0)))
  return Math.max(4, Math.min(100, (Number(count || 0) / max) * 100))
}

function modelDescription(item) {
  const modelDescriptions = {
    MalConv: '直接读取文件字节序列，用较长的上下文寻找恶意代码、填充区和异常编码留下的整体模式。适合快速判断文件内容是否呈现已知恶意结构。',
    MalConv2: '在字节级模型基础上强化局部片段与长距离依赖的建模，关注入口附近、节区边界和高风险片段，为最终判定提供内容证据。',
    ByteTransformer: '使用注意力机制比较不同位置的字节片段，捕捉跨节区关联、混淆片段和重复载荷等序列关系，补充传统统计模型的盲区。',
    SaxeBerlinDNN: '针对 PE 静态特征进行深度非线性建模，综合文件结构、导入信息和基础属性，识别多种特征共同出现时的风险变化。',
    EmberDNN: '学习 EMBER 风格的 PE 特征组合，包括头部、节区、导入、字符串和熵等信息，用于评估文件的综合恶意概率。',
    NatarajKNN: '比较当前文件与特征空间中相近样本的距离，寻找与历史恶意文件相似的结构模式，结果便于解释和追溯近邻样本。',
    DrebinSVM: '基于可解释的静态特征边界进行分类，重点观察权限、调用、字符串和结构信号的组合，适合作为稳定的基线判断。',
    DL4MD: '从多类恶意软件静态特征中学习层次化表示，识别常见家族的组合特征和变种漂移，提供面向家族的风险参考。',
    PEMinerRF: '通过随机森林分析 PE 头、节表、导入和资源等离散特征，利用多棵决策树交叉判断异常结构，结果具有较好的可读性。',
    DrebinImport: '专门分析导入 API 与库的组合，关注进程注入、持久化、网络通信和系统修改等能力是否同时出现。',
    ALOHANet: '从多源静态特征中学习恶意软件的非线性关联，关注单个特征不明显但组合后具有辨识度的行为线索。',
    EmberGBDT_Import: '将 EMBER 特征与导入表统计交给梯度提升树分析，重点识别 API 组合、调用密度和文件结构之间的异常关系。',
    RaffFeatureNet: '对经过筛选和编码的 PE 特征进行深度表示学习，减少冗余字段影响，突出对恶意判别更有贡献的特征。',
    DrebinString: '提取 URL、命令行、路径、注册表和脚本等字符串信号，识别下载执行、持久化和远程控制相关内容。',
    OpcodeLSTM: '按顺序读取反汇编操作码，利用循环网络观察指令之间的先后关系，寻找解码、注入和加载器常见的代码节奏。',
    OpcodeTransformer: '使用注意力机制分析更长的操作码上下文，比较不同函数和代码区域之间的关联，适合发现复杂的指令组合。',
    OpcodeStatNet: '统计算术、跳转、调用、内存访问等指令类别及其 n-gram 分布，用代码风格变化发现异常编译或混淆痕迹。',
    AsmEmbedNet: '把汇编函数编码成向量，比较函数级语义和结构相似性，辅助识别常见加载器、解密例程和恶意功能片段。',
    MalGraph: '把函数与调用关系组织成图，观察节点连接、调用深度和关键路径，补充单纯字节或统计特征无法表达的结构信息。',
    CFGGAT: '在控制流图上使用图注意力聚合关键邻居，突出分支、循环和异常跳转等结构，识别复杂函数中的可疑控制逻辑。',
    CFGGCN: '通过图卷积传播控制流节点信息，学习基本块之间的局部结构模式，评估函数是否具有恶意代码常见的控制流形态。',
    CFGDGCNN: '对控制流图进行动态卷积式聚合，关注不同规模的子图结构和异常路径，提升对变形代码与复杂分支的识别能力。',
    CallGraphGNN: '分析函数调用图中的入口、中心节点和调用链，定位网络、进程、文件和注册表能力之间的组合关系。',
    GraphStatNet: '把图的节点数、边数、深度、度分布等统计量进行联合建模，用整体图形态快速筛查异常程序结构。',
    GrayscaleCNN: '将文件字节排列为灰度图像，利用纹理、密度和区域边界识别压缩、填充、重复载荷及代码区域的视觉模式。',
    InceptionV3: '从字节可视化图像中提取多尺度纹理特征，兼顾局部高密度区域与整体布局，为视觉检测链路提供成熟的图像表征。',
    IMCFN: '融合多通道文件图像信息，比较不同通道中的纹理和边缘变化，识别仅在某一种视觉表示中明显的恶意模式。',
    ColorCNN: '把字节映射到彩色通道并分析颜色纹理，观察不同数据区域的通道关系，为灰度图难以区分的样本提供补充证据。',
    MarkovCNN: '根据字节状态转移构造马尔可夫图像，分析相邻状态变化和重复转移路径，寻找编码、解码及混淆带来的规律。',
    EntropyMapCNN: '把局部熵变化绘制成热度图，定位高熵压缩区、低熵填充区和突变边界，帮助判断打包、加密与载荷分布。',
    HashEmbedNet: '联合建模文件哈希与相似性摘要，利用内容指纹关联相近样本，为样本库命中之外的变种识别提供线索。',
    MetadataNet: '分析版本信息、清单、资源、签名和编译元数据，检查声明信息是否缺失、矛盾或与可疑文件行为不一致。',
    ResourceNet: '专注 PE 资源、图标、清单和嵌入对象，识别异常资源大小、类型组合及隐藏载荷等资源层面的风险。'
  }
  if (modelDescriptions[item.name]) return modelDescriptions[item.name]
  const view = String(item.view || '').toLowerCase()
  const descriptions = [
    [/byte-level/, '直接观察文件原始字节序列中的局部模式，为分析提供最接近文件内容本身的证据。'],
    [/bytestat/, '统计字节分布与熵特征，寻找可疑编码、压缩或打包行为留下的结构痕迹。'],
    [/pe-struct/, '读取 PE 头部与节区等静态结构，评估文件布局和关键字段是否呈现异常模式。'],
    [/import/, '分析导入表中的 API 与依赖组合，观察程序声明需要调用的系统能力。'],
    [/string/, '从文件中提取可读字符串及其统计信息，辅助发现命令、路径和可疑配置线索。'],
    [/opcodeseq/, '读取反汇编后的指令序列，学习操作码的先后关系与代码行为模式。'],
    [/opcodestat/, '统计指令类别与 n-gram 分布，以紧凑特征描述代码的整体风格。'],
    [/funcembed/, '把汇编函数映射为向量表示，比较函数级代码结构和行为特征。'],
    [/graph/, '从控制流或函数调用关系观察代码连接方式，补充单纯统计特征看不到的结构信息。'],
    [/grayvis/, '将文件字节映射为灰度图像，通过纹理和区域变化识别具有区分度的视觉模式。'],
    [/colorvis/, '将字节内容映射为彩色图像，利用颜色通道间的纹理差异补充视觉分析线索。'],
    [/markovvis/, '以字节状态转移关系构造图像，观察文件内容在状态之间的变化规律。'],
    [/entropyvis/, '把局部熵变化绘制为热度分布，定位数据密度和编码规律显著变化的区域。'],
    [/hash/, '对多种文件哈希与相似性摘要进行联合表示，提供基于内容指纹的风险线索。'],
    [/metadata/, '分析版本信息、资源、清单等元数据，检查文件声明和资源布局中的异常信号。']
  ]
  return descriptions.find(([pattern]) => pattern.test(view))?.[1]
    || `基于 ${item.view || '多视角特征'} 提取的 ${item.features || '项目特征'} 进行独立判别，为综合结果提供补充证据。`
}

function normalizeDetectionResponse(data) {
  const queryResult = data.query_result || {}
  return {
    ...data,
    filename: data.filename || data.original_filename || queryResult.name || '-',
    sha256: data.sha256 || queryResult['SHA-256'] || queryResult.SHA256 || '',
    md5: data.md5 || queryResult.MD5 || '',
    file_size: data.file_size || queryResult['文件大小'] || 0,
    file_type: data.file_type || queryResult['文件类型'] || queryResult['类型'] || '-',
    detection_time: data.detection_time || new Date().toLocaleString(),
    file_header: data.file_header || data.pe_info?.header || '',
    exe_result: data.exe_result || data.results || {},
    pe_info: data.pe_info || {}
  }
}

function formatFileSize(value) {
  if (value === null || value === undefined || value === '') return '-'
  if (typeof value === 'string' && value.includes('bytes')) {
    value = Number.parseInt(value, 10)
  } else if (typeof value === 'string') {
    return value
  }
  const bytes = Number(value)
  if (!Number.isFinite(bytes)) return '-'
  const units = ['B', 'KB', 'MB', 'GB']
  const index = Math.min(Math.floor(Math.log(bytes || 1) / Math.log(1024)), units.length - 1)
  return `${Math.round((bytes / Math.pow(1024, index)) * 100) / 100} ${units[index]}`
}

function formatNumber(value) {
  return Number(value || 0).toLocaleString('zh-CN')
}

function getProbabilityPercent(probability) {
  if (probability === null || probability === undefined) return 0
  if (typeof probability === 'string') return Number.parseFloat(probability.replace('%', '')) || 0
  return Math.round(Number(probability) * 10000) / 100
}

function getProbabilityColor(probability) {
  const percent = getProbabilityPercent(probability)
  if (percent >= 70) return '#d94f45'
  if (percent >= 40) return '#b7791f'
  return '#2f855a'
}
</script>
