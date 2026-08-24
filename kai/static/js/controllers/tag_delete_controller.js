import { Controller } from "@hotwired/stimulus"

export default class extends Controller {
  static targets = ["modal", "message", "form"]

  show(event) {
    const name = event.params.name
    const count = parseInt(event.params.count, 10)
    const url = event.params.url

    let msg
    if (count > 0) {
      const noun = count === 1 ? "capture" : "captures"
      const ref = count === 1 ? "that file" : "those files"
      msg = `Tag "${name}" is attached to ${count} ${noun}. Deleting it will remove this tag from ${ref}.`
    } else {
      msg = `Delete tag "${name}"? This tag is not used by any captures.`
    }

    this.messageTarget.textContent = msg
    this.formTarget.action = url
    this.modalTarget.classList.remove("hidden")

    this._onKeydown = this._handleKeydown.bind(this)
    document.addEventListener("keydown", this._onKeydown)
  }

  hide() {
    this.modalTarget.classList.add("hidden")
    if (this._onKeydown) {
      document.removeEventListener("keydown", this._onKeydown)
      this._onKeydown = null
    }
  }

  stopProp(event) {
    event.stopPropagation()
  }

  _handleKeydown(event) {
    if (event.key === "Escape") this.hide()
  }
}
