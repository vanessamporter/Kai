import { Controller } from "@hotwired/stimulus"

export default class extends Controller {
  toggle() {
    const current = document.documentElement.dataset.theme
    const next = current === "dark" ? "light" : "dark"

    document.documentElement.classList.add("theme-transitioning")
    document.documentElement.dataset.theme = next
    localStorage.setItem("kai-theme", next)

    setTimeout(() => {
      document.documentElement.classList.remove("theme-transitioning")
    }, 350)
  }
}
