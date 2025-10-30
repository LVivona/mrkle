# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html
# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information
import sys
import os

cd = os.path.dirname(os.path.abspath(__file__))
assets = os.path.join(cd, "..", "..", "..", ".github", "assets")
sys.path.insert(
    0,
    os.path.join(
        os.path.abspath(os.path.dirname(os.path.dirname(__file__))), "py", "mrkle"
    ),
)

project = "mrkle"
copyright = "2025, Luca Vivona"
author = "Luca Vivona"
release = "0.0.1"

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    "sphinx.ext.napoleon",
    "sphinx.ext.autodoc",
    "sphinx.ext.viewcode",
    "sphinx.ext.intersphinx",
    "sphinx.ext.autosummary",
]

autodoc_default_options = {"ignore-module-all": True}
templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

favicon_url = "favicon.ico"
html_permalinks_icon = "<span>¶</span>"
html_theme = "sphinxawesome_theme"
html_title = "mrkle"
html_logo = os.path.join(assets, "logo.png")
html_extra_path = [assets]

html_theme_options = {
    "show_breadcrumbs": True,
    "show_scrolltop": True,
    "show_prev_next": True,
    "extra_header_link_icons": {
        "github": dict(
            icon="""<svg fill="currentColor" height="26px" style="margin-top:-2px;display:inline" viewBox="0 0 45 44" xmlns="http://www.w3.org/2000/svg"><path clip-rule="evenodd" d="M22.477.927C10.485.927.76 10.65.76 22.647c0 9.596 6.223 17.736 14.853 20.608 1.087.2 1.483-.47 1.483-1.047 0-.516-.019-1.881-.03-3.693-6.04 1.312-7.315-2.912-7.315-2.912-.988-2.51-2.412-3.178-2.412-3.178-1.972-1.346.149-1.32.149-1.32 2.18.154 3.327 2.24 3.327 2.24 1.937 3.318 5.084 2.36 6.321 1.803.197-1.403.759-2.36 1.379-2.903-4.823-.548-9.894-2.412-9.894-10.734 0-2.37.847-4.31 2.236-5.828-.224-.55-.969-2.759.214-5.748 0 0 1.822-.584 5.972 2.226 1.732-.482 3.59-.722 5.437-.732 1.845.01 3.703.25 5.437.732 4.147-2.81 5.967-2.226 5.967-2.226 1.185 2.99.44 5.198.217 5.748 1.392 1.517 2.232 3.457 2.232 5.828 0 8.344-5.078 10.18-9.916 10.717.779.67 1.474 1.996 1.474 4.021 0 2.904-.027 5.247-.027 5.96 0 .58.392 1.256 1.493 1.044C37.981 40.375 44.2 32.24 44.2 22.647c0-11.996-9.726-21.72-21.722-21.72" fill="currentColor" fill-rule="evenodd"></path></svg>""",
            link="https://github.com/LVivona/mrkle",
        )
    },
}

# Add sidebar with TOC
html_sidebars = {"**": ["sidebar_main_nav_links.html", "sidebar_toc.html"]}
