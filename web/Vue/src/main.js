import { createApp } from 'vue'
import {
  ElButton, ElCollapse, ElCollapseItem, ElDescriptions, ElDescriptionsItem,
  ElIcon, ElProgress, ElRadioButton, ElRadioGroup, ElTable, ElTableColumn, ElTag
} from 'element-plus'
import 'element-plus/es/components/button/style/css'
import 'element-plus/es/components/collapse/style/css'
import 'element-plus/es/components/descriptions/style/css'
import 'element-plus/es/components/icon/style/css'
import 'element-plus/es/components/progress/style/css'
import 'element-plus/es/components/radio-button/style/css'
import 'element-plus/es/components/radio-group/style/css'
import 'element-plus/es/components/table/style/css'
import 'element-plus/es/components/tag/style/css'
import 'element-plus/es/components/message/style/css'
import App from './App.vue'
import './styles.css'

const app = createApp(App)
for (const component of [ElButton, ElCollapse, ElCollapseItem, ElDescriptions,
  ElDescriptionsItem, ElIcon, ElProgress, ElRadioButton, ElRadioGroup,
  ElTable, ElTableColumn, ElTag]) {
  app.component(component.name, component)
}
app.mount('#app')
