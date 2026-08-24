import { Controller } from "@hotwired/stimulus"

// Auto-submits the search form via Turbo Frame on input changes with debounce.
// Updates URL via replaceState so search is bookmarkable.
// Usage: <form data-controller="search-form" data-turbo-frame="pcap_results">
export default class extends Controller {
  connect() {
    this.timeout = null
    this.element.addEventListener("input", this.#debounceSubmit)
    this.element.addEventListener("change", this.#debounceSubmit)
  }

  disconnect() {
    this.element.removeEventListener("input", this.#debounceSubmit)
    this.element.removeEventListener("change", this.#debounceSubmit)
    if (this.timeout) clearTimeout(this.timeout)
  }

  #debounceSubmit = () => {
    if (this.timeout) clearTimeout(this.timeout)
    this.timeout = setTimeout(() => {
      this.#updateUrl()
      this.element.requestSubmit()
    }, 200)
  }

  #updateUrl() {
    const formData = new FormData(this.element)
    const params = new URLSearchParams()
    for (const [key, value] of formData) {
      if (value) params.set(key, value)
    }
    const query = params.toString()
    const url = query ? `${this.element.action}?${query}` : this.element.action
    history.replaceState(null, "", url)
  }
}
