<template>
  <main class="page-shell">
    <section class="header">
      <div>
        <h1>NKAMG-AIDefender 多模型恶意文件检测</h1>
        <p>南开大学反病毒实验室NKAMG - 支持33个检测模型</p>
      </div>
      <div class="status-tags">
        <el-tag size="large" :type="modelService.ready ? 'success' : modelService.connected ? 'warning' : 'danger'">
          {{ checkingModels ? '正在检查模型服务' : modelService.ready ? `模型服务已连接（${modelService.model_count}个）` : modelService.connected ? '模型服务未就绪' : '模型服务未连接' }}
        </el-tag>
      </div>
    </section>

    <section class="workbench">
      <div class="upload-zone" @drop="handleDrop" @dragover.prevent>
        <input ref="fileInput" class="hidden-input" type="file" @change="handleFileChange" />
        <el-icon class="upload-icon"><UploadFilled /></el-icon>
        <div class="upload-title">上传PE样本进行检测</div>
        <div class="upload-subtitle">后端会先校验PE结构，计算基础信息，再提交给模型分析。</div>
        <el-button type="primary" :loading="loading" @click="selectFile">选择待检PE文件</el-button>
        <div v-if="loading" class="upload-subtitle" role="status">{{ detectionMessage }}</div>
      </div>

      <el-collapse class="models-collapse">
        <el-collapse-item title="33个模型说明与NKAMG样本库数据" name="models">
          <h3 class="subhead">支持模型与作用（{{ modelDetails.length }}个）</h3>
          <el-table :data="modelDetails" border stripe size="small">
            <el-table-column prop="name" label="模型" min-width="140" />
            <el-table-column prop="view" label="分析视角" min-width="120" />
            <el-table-column prop="features" label="使用特征" min-width="160" />
            <el-table-column prop="source" label="参考来源" min-width="200" />
            <el-table-column prop="role" label="模型作用" min-width="240" />
            <el-table-column prop="optimization" label="优化要点" min-width="260" />
          </el-table>
          <h3 class="subhead">恶意文件样本统计</h3>
          <div v-if="stats.available" class="stats-grid">
            <div class="stat-item"><span>恶意样本总量</span><strong>{{ formatNumber(stats.samples?.malicious_total) }}</strong></div>
            <div class="stat-item"><span>良性样本总量</span><strong>{{ formatNumber(stats.samples?.benign_total) }}</strong></div>
            <div v-for="field in sampleTopFields" :key="field.key"><span>{{ field.label }} Top10</span><div v-for="item in stats.samples?.[field.key] || []" :key="item.name">{{ item.name }}：{{ formatNumber(item.count) }}</div></div>
          </div>
          <p v-else class="muted-text">{{ stats.reason || '统计数据暂不可用' }}</p>
          <div v-if="stats.available && stats.samples?.monthly?.length" class="stats-monthly">
            <span>近 12 个月恶意样本</span>
            <div v-for="item in stats.samples.monthly" :key="item.name">{{ item.name }}：{{ formatNumber(item.count) }}</div>
          </div>
          <h3 class="subhead">恶意域名统计</h3>
          <div v-if="stats.available" class="stats-grid">
            <div class="stat-item"><span>域名总量</span><strong>{{ formatNumber(stats.domains?.total) }}</strong></div>
            <div v-for="field in domainTopFields" :key="field.key"><span>{{ field.label }} Top10</span><div v-for="item in stats.domains?.[field.key] || []" :key="item.name">{{ item.name }}：{{ formatNumber(item.count) }}</div></div>
          </div>
          <p v-else class="muted-text">{{ stats.reason || '统计数据暂不可用' }}</p>
          <div v-if="stats.available && stats.domains?.monthly?.length" class="stats-monthly">
            <span>近 12 个月恶意域名</span>
            <div v-for="item in stats.domains.monthly" :key="item.name">{{ item.name }}：{{ formatNumber(item.count) }}</div>
          </div>
          <p v-if="stats.available" class="muted-text">数据更新时间：{{ stats.updated_at || '-' }}</p>
        </el-collapse-item>
      </el-collapse>
    </section>

    <section v-if="uploadResult" class="results">
      <div class="result-head">
        <div>
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
          <h3 class="subhead">样本标识</h3>
          <el-descriptions :column="1" border>
            <el-descriptions-item v-for="(value, key) in uploadResult.sample_record.identity" :key="key" :label="key">{{ key === '文件大小' ? formatFileSize(value) : value }}</el-descriptions-item>
          </el-descriptions>
          <h3 class="subhead">哈希信息</h3>
          <el-descriptions :column="1" border>
            <el-descriptions-item v-for="(value, key) in uploadResult.sample_record.hashes" :key="key" :label="key">{{ value || '-' }}</el-descriptions-item>
          </el-descriptions>
          <h3 class="subhead">样本标签</h3>
          <el-descriptions :column="2" border>
            <el-descriptions-item v-for="(value, key) in uploadResult.sample_record.labels" :key="key" :label="key">{{ value || '-' }}</el-descriptions-item>
          </el-descriptions>
        </template>
        <el-descriptions :column="1" border>
          <el-descriptions-item v-if="!uploadResult.database_hit" label="文件名">{{ uploadResult.filename || '-' }}</el-descriptions-item>
          <el-descriptions-item label="SHA256">
            <span class="mono break-text">{{ uploadResult.sha256 || '-' }}</span>
          </el-descriptions-item>
          <el-descriptions-item label="MD5">
            <span class="mono break-text">{{ uploadResult.md5 || uploadResult.query_result?.MD5 || '-' }}</span>
          </el-descriptions-item>
          <el-descriptions-item v-if="!uploadResult.database_hit" label="文件大小">{{ formatFileSize(uploadResult.file_size) }}</el-descriptions-item>
          <el-descriptions-item label="文件类型">{{ uploadResult.file_type || '-' }}</el-descriptions-item>
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
          <el-tag size="large" type="info">共 {{ modelCount }} 个检测模型</el-tag>
          <el-tag size="large" type="danger">恶意: {{ maliciousCount }}</el-tag>
          <el-tag size="large" type="success">安全: {{ safeCount }}</el-tag>
        </div>
        <el-table :data="modelRows" border stripe class="model-table">
          <el-table-column type="index" label="序号" width="70" />
          <el-table-column prop="model" label="检测模型" min-width="180" />
          <el-table-column label="恶意概率" min-width="180">
            <template #default="{ row }">
              <el-progress :percentage="getProbabilityPercent(row.probability)" :color="getProbabilityColor(row.probability)" />
            </template>
          </el-table-column>
          <el-table-column label="结果" width="120">
            <template #default="{ row }">
              <el-tag :type="row.result === '恶意' ? 'danger' : row.result === '安全' ? 'success' : 'info'">
                {{ row.result }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="virus_name" label="病毒名称" min-width="180">
            <template #default="{ row }">{{ row.virus_name || '-' }}</template>
          </el-table-column>
        </el-table>
        </template>
      </div>
    </section>
  </main>
</template>

<script setup>
import axios from 'axios'
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { UploadFilled } from '@element-plus/icons-vue'

const apiService = axios.create({ timeout: 600000 })

const showSection = ref('fileInfo')
const loading = ref(false)
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

const sectionOptions = [
  { label: '基础信息', value: 'fileInfo' },
  { label: '模型检测', value: 'modelDetection' }
]

const peInfo = computed(() => uploadResult.value?.pe_info || {})

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
  virus_name: data.virus_name
})))

const modelCount = computed(() => modelRows.value.length)
const maliciousCount = computed(() => modelRows.value.filter(row => row.result === '恶意').length)
const safeCount = computed(() => modelRows.value.filter(row => row.result === '安全').length)

onMounted(async () => {
  loading.value = Boolean(localStorage.getItem(TASK_KEY))
  await loadConfig()
  void Promise.allSettled([loadModels(), loadModelHealth(), loadStats()])
  modelHealthTimer = window.setInterval(loadModelHealth, 30000)
  await restoreDetectionTask()
})
onUnmounted(() => {
  detectionAbort.abort()
  window.clearInterval(modelHealthTimer)
})

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
  resetResult()
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
      uploadResult.value = normalizeDetectionResponse(response.data)
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
        uploadResult.value = normalizeDetectionResponse(task.result || {})
        // Keep the ID until a new upload, so refreshing a completed report
        // also restores it during the server's configured retention period.
        localStorage.setItem(TASK_PHASE_KEY, 'accepted')
        ElMessage.success('检测完成')
        return
      }
      if (task.status === 'failed') {
        clearSavedTask()
        throw new Error(task.error || '检测任务失败')
      }
      localStorage.setItem(TASK_PHASE_KEY, 'accepted')
      detectionMessage.value = '正在检测，可刷新页面继续等待'
      await new Promise(resolve => window.setTimeout(resolve, 2500))
    }
  } catch (error) {
    if (detectionAbort.signal.aborted) return
    ElMessage.error('检测失败: ' + (error.response?.data?.detail || error.message))
  } finally {
    loading.value = false
  }
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
