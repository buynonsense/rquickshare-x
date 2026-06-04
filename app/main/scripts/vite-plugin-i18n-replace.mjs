import { readFileSync } from 'fs'
import { resolve, dirname } from 'path'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))

const escapeRegex = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')

export default function i18nReplace() {
	const mapPath = resolve(__dirname, '../locales/zh-CN.json')
	const raw = JSON.parse(readFileSync(mapPath, 'utf-8'))

	// 按长度降序排列，长串优先匹配
	const entries = Object.entries(raw).sort(
		(a, b) => b[0].length - a[0].length
	)

	return {
		name: 'vite-plugin-i18n-replace',
		enforce: 'pre',
		transform(code, id) {
			if (!id.endsWith('.vue')) return null

			let result = code
			for (const [from, to] of entries) {
				const escaped = escapeRegex(from)
				const regex = new RegExp(
					`(^|(?<=\\W))${escaped}($|(?=\\W))`,
					'g'
				)
				result = result.replace(regex, to)
			}

			return { code: result, map: null }
		}
	}
}
