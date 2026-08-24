import { Controller } from "@hotwired/stimulus"

export default class extends Controller {
  static targets = ["input"]

  startEdit() {
    this.element.classList.add("editing")
    this.inputTarget.focus()
    this.inputTarget.select()
  }

  cancelEdit() {
    this.element.classList.remove("editing")
  }

  handleKeydown(event) {
    if (event.key === "Escape") {
      this.cancelEdit()
    }
  }
}
