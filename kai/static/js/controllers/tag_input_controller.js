import { Controller } from "@hotwired/stimulus"

// Custom tag input with per-tag entry and remote autocomplete.
// Enter adds a tag, comma splits and adds, Backspace removes last tag.
// Usage:
//   <div data-controller="tag-input" data-tag-input-url-value="/tags">
//     <div data-tag-input-target="container" class="tag-input-container">
//       <input type="text" data-tag-input-target="input" class="tag-input-field">
//     </div>
//     <input type="hidden" name="pcap[tag_list]" data-tag-input-target="hidden" value="existing,tags">
//     <div data-tag-input-target="dropdown" class="tag-input-dropdown hidden" role="listbox"></div>
//   </div>
export default class extends Controller {
  static targets = ["container", "input", "hidden", "dropdown"]
  static values = { url: { type: String, default: "/tags" } }

  connect() {
    this.tags = []
    this.activeIndex = -1
    this.debounceTimer = null
    this.suggestions = []
    this.truncatedCount = 0

    // Parse initial tags from hidden input
    const initial = this.hiddenTarget.value
    if (initial) {
      initial.split(",").map(t => t.trim()).filter(Boolean).forEach(t => this._addTag(t, false))
    }

    // ARIA
    this.inputTarget.setAttribute("role", "combobox")
    this.inputTarget.setAttribute("aria-autocomplete", "list")
    this.inputTarget.setAttribute("aria-expanded", "false")

    // Events on the input
    this._onKeyDown = this.handleKeyDown.bind(this)
    this._onInput = this.handleInput.bind(this)
    this._onPaste = this.handlePaste.bind(this)
    this._onFocus = this.handleFocus.bind(this)
    this.inputTarget.addEventListener("keydown", this._onKeyDown)
    this.inputTarget.addEventListener("input", this._onInput)
    this.inputTarget.addEventListener("paste", this._onPaste)
    this.inputTarget.addEventListener("focus", this._onFocus)

    // Close dropdown on outside click
    this._onClickOutside = (e) => {
      if (!this.element.contains(e.target)) this.closeDropdown()
    }
    document.addEventListener("mousedown", this._onClickOutside)

    // Click on container focuses input
    this.containerTarget.addEventListener("click", () => this.inputTarget.focus())
  }

  disconnect() {
    document.removeEventListener("mousedown", this._onClickOutside)
    clearTimeout(this.debounceTimer)
  }

  // --- Key handling ---

  handleKeyDown(e) {
    switch (e.key) {
      case "Enter":
        e.preventDefault()
        if (this.activeIndex >= 0 && this.suggestions[this.activeIndex]) {
          this._addTag(this.suggestions[this.activeIndex])
        } else {
          const val = this.inputTarget.value.trim()
          if (val) this._addTag(val)
        }
        break
      case "Backspace":
        if (!this.inputTarget.value && this.tags.length) {
          this._removeTag(this.tags[this.tags.length - 1])
        }
        break
      case "Escape":
        this.closeDropdown()
        break
      case "ArrowDown":
        e.preventDefault()
        this._navigate(1)
        break
      case "ArrowUp":
        e.preventDefault()
        this._navigate(-1)
        break
    }
  }

  handleInput() {
    const val = this.inputTarget.value

    // Comma splits immediately
    if (val.includes(",")) {
      val.split(",").map(t => t.trim()).filter(Boolean).forEach(t => this._addTag(t))
      return
    }

    clearTimeout(this.debounceTimer)
    this.debounceTimer = setTimeout(() => this._fetchSuggestions(val.trim()), 200)
  }

  handlePaste(e) {
    e.preventDefault()
    const text = (e.clipboardData || window.clipboardData).getData("text")
    text.split(/[,\n]+/).map(t => t.trim()).filter(Boolean).forEach(t => this._addTag(t))
  }

  handleFocus() {
    this._fetchSuggestions(this.inputTarget.value.trim())
  }

  // --- Tag management ---

  _addTag(name, sync = true) {
    name = name.toLowerCase().trim()
    if (!name || this.tags.includes(name)) {
      this.inputTarget.value = ""
      this.closeDropdown()
      return
    }

    this.tags.push(name)
    this._renderPill(name)
    this.inputTarget.value = ""
    this.closeDropdown()
    if (sync) this._syncHidden()
  }

  _removeTag(name) {
    this.tags = this.tags.filter(t => t !== name)
    const pill = this.containerTarget.querySelector(`[data-tag="${CSS.escape(name)}"]`)
    if (pill) {
      pill.classList.add("removing")
      pill.addEventListener("animationend", () => pill.remove(), { once: true })
    }
    this._syncHidden()
    this.inputTarget.focus()
  }

  _renderPill(name) {
    const pill = document.createElement("span")
    pill.className = "tag-input-pill"
    pill.dataset.tag = name

    const label = document.createElement("span")
    label.textContent = name

    const btn = document.createElement("button")
    btn.type = "button"
    btn.className = "tag-input-pill-x"
    btn.tabIndex = -1
    btn.setAttribute("aria-label", `Remove ${name}`)
    btn.textContent = "×"
    btn.addEventListener("click", (e) => {
      e.stopPropagation()
      this._removeTag(name)
    })

    pill.appendChild(label)
    pill.appendChild(btn)
    this.containerTarget.insertBefore(pill, this.inputTarget)
  }

  _syncHidden() {
    this.hiddenTarget.value = this.tags.join(",")
    this.hiddenTarget.dispatchEvent(new Event("input", { bubbles: true }))
    this.hiddenTarget.dispatchEvent(new Event("change", { bubbles: true }))
  }

  // --- Autocomplete ---

  async _fetchSuggestions(query) {
    try {
      const url = query
        ? `${this.urlValue}.json?q=${encodeURIComponent(query)}`
        : `${this.urlValue}.json`
      const r = await fetch(url)
      const data = await r.json()
      this.suggestions = data.tags.filter(n => !this.tags.includes(n.toLowerCase()))
      this.truncatedCount = data.total > data.tags.length ? data.total - data.tags.length : 0
      this._renderDropdown()
    } catch {
      this.closeDropdown()
    }
  }

  _renderDropdown() {
    if (!this.suggestions.length) {
      this.closeDropdown()
      return
    }

    this.activeIndex = -1
    const fragment = document.createDocumentFragment()
    this.suggestions.forEach((name, index) => {
      const item = document.createElement("div")
      item.className = "tag-input-dropdown-item"
      item.dataset.index = index
      item.setAttribute("role", "option")
      item.textContent = name
      fragment.appendChild(item)
    })
    if (this.truncatedCount > 0) {
      const more = document.createElement("div")
      more.className = "tag-input-dropdown-more"
      more.textContent = `+${this.truncatedCount} more — type to filter`
      fragment.appendChild(more)
    }
    this.dropdownTarget.replaceChildren(fragment)
    this.dropdownTarget.classList.remove("hidden")
    this.inputTarget.setAttribute("aria-expanded", "true")

    // Mousedown (not click) so it fires before blur
    this.dropdownTarget.querySelectorAll(".tag-input-dropdown-item").forEach(item => {
      item.addEventListener("mousedown", (e) => {
        e.preventDefault()
        this._addTag(this.suggestions[parseInt(item.dataset.index)])
      })
    })
  }

  closeDropdown() {
    this.dropdownTarget.classList.add("hidden")
    this.dropdownTarget.replaceChildren()
    this.suggestions = []
    this.activeIndex = -1
    this.inputTarget.setAttribute("aria-expanded", "false")
  }

  _navigate(dir) {
    if (!this.suggestions.length) return
    this.activeIndex = Math.max(-1, Math.min(this.suggestions.length - 1, this.activeIndex + dir))
    this.dropdownTarget.querySelectorAll(".tag-input-dropdown-item").forEach((item, i) => {
      item.classList.toggle("active", i === this.activeIndex)
      if (i === this.activeIndex) item.scrollIntoView({ block: "nearest" })
    })
  }

}
