<!--
  ~ Licensed to the Apache Software Foundation (ASF) under one
  ~ or more contributor license agreements.  See the NOTICE file
  ~ distributed with this work for additional information
  ~ regarding copyright ownership.  The ASF licenses this file
  ~ to you under the Apache License, Version 2.0 (the
  ~ "License"); you may not use this file except in compliance
  ~ with the License.  You may obtain a copy of the License at
  ~
  ~    https://www.apache.org/licenses/LICENSE-2.0
  ~
  ~ Unless required by applicable law or agreed to in writing,
  ~ software distributed under the License is distributed on an
  ~ "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
  ~ KIND, either express or implied.  See the License for the
  ~ specific language governing permissions and limitations
  ~ under the License.
-->

<script setup lang="ts">
  import { storeToRefs } from 'pinia'
  import { onMounted } from 'vue'
  import { useLocaleStore } from '@/store/locale'
  import { useThemeStore } from './store/theme'
  const themeStore = useThemeStore()
  const localeStore = useLocaleStore()
  const { antd } = storeToRefs(localeStore)
  const { themeConfig } = storeToRefs(themeStore)

  onMounted(() => {
    themeStore.initTheme()
  })
</script>

<template>
  <a-config-provider :locale="antd" :theme="themeConfig">
    <a-app class="app">
      <router-view />
    </a-app>
  </a-config-provider>
</template>

<style scoped lang="scss">
  .app {
    overflow: hidden;
  }
</style>
