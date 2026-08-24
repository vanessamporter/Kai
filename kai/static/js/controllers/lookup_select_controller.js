import { Controller } from "@hotwired/stimulus"
import TomSelect from "tom-select"

// Wraps Tom Select for lookup value dropdowns with remote autocomplete.
// Usage: <select data-controller="lookup-select"
//               data-lookup-select-category-value="sector"
//               data-lookup-select-url-value="/lookup_values"
//               data-lookup-select-allow-create-value="true">
export default class extends Controller {
  static values = {
    url: { type: String, default: "/lookup_values" },
    category: String,
    allowCreate: { type: Boolean, default: false }
  }

  connect() {
    const isMultiple = this.element.multiple

    this.select = new TomSelect(this.element, {
      plugins: isMultiple ? ["remove_button"] : [],
      create: this.allowCreateValue ? this.#handleCreate.bind(this) : false,
      maxOptions: 20,
      valueField: "value",
      labelField: "text",
      searchField: "text",
      load: (query, callback) => {
        const params = new URLSearchParams({ category: this.categoryValue })
        if (query.length) params.set("q", query)
        fetch(`${this.urlValue}?${params}`)
          .then(r => r.json())
          .then(values => callback(values.map(v => ({ value: v, text: v }))))
          .catch(() => callback())
      },
      render: {
        option_create: function(data, escape) {
          return `<div class="create">Add <strong>${escape(data.input)}</strong>&hellip;</div>`
        }
      }
    })
  }

  disconnect() {
    if (this.select) this.select.destroy()
  }

  #handleCreate(input, callback) {
    fetch(this.urlValue, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": document.querySelector("meta[name=csrf-token]")?.content
      },
      body: JSON.stringify({ category: this.categoryValue, value: input })
    })
      .then(r => r.json())
      .then(data => callback({ value: data.value, text: data.value }))
      .catch(() => callback())
  }
}
