# Thesis: «Probolos: Πύλη Αποδοχής Συσκευών USB με Προεπιλεγμένη Άρνηση για το Linux»

A master's thesis in Greek, written in LaTeX, about this tool. It builds with
**XeLaTeX + Biber**, which handles Greek text and Unicode natively.

## Build on Manjaro

### 1. Install TeX Live (once)

```bash
sudo pacman -S --needed texlive-basic texlive-latex texlive-latexrecommended \
  texlive-latexextra texlive-xetex texlive-langgreek texlive-fontsrecommended \
  texlive-fontsextra texlive-pictures texlive-mathscience texlive-bibtexextra \
  texlive-binextra biber ttf-dejavu
```

If you have disk space and want to skip the package list, install everything:

```bash
sudo pacman -S --needed texlive texlive-lang biber ttf-dejavu
```

### 2. Build the PDF

```bash
cd thesis
latexmk -xelatex main.tex        # -> main.pdf
```

The same thing via the Makefile: `make` builds, `make watch` rebuilds on every
save, and `make clean` removes the build files.

Without latexmk, run the four passes by hand:

```bash
xelatex main && biber main && xelatex main && xelatex main
```

## Before you submit

Search for `[` placeholders and fill them in:

- `main.tex`: university, programme, your name, student ID, supervisor,
  committee, city and date;
- `frontmatter/cover.tex`: replace the placeholder circle with your
  university's logo (`\includegraphics{figures/logo.pdf}`);
- `frontmatter/acknowledgements.tex` and `frontmatter/dedication.tex`;
- `chapters/06_evaluation.tex`, §6.8 (Table 6.6): the real-hardware
  measurements are not done yet. Fill them in, or move them to future work.

Check your department's template. Many Greek universities require their own
cover page, margins or citation style, so adjust `preamble.tex` and
`frontmatter/cover.tex` to match.

## Layout

| Path | Contents |
|---|---|
| `main.tex` | document skeleton and thesis details (fill in) |
| `preamble.tex` | packages, fonts, colours, code style |
| `frontmatter/` | cover, title page, declaration, acknowledgements, abstracts (Greek + English), acronyms |
| `chapters/` | 1 Introduction · 2 Background · 3 Threat model & related work · 4 Design · 5 Implementation · 6 Evaluation · 7 Discussion · 8 Conclusions |
| `appendices/` | A Installation & usage · B All rules · C Output examples |
| `references.bib` | bibliography (biblatex) |

## Where the numbers come from

- **1413 tests:** `python3 -m unittest discover -b -s tests -t .` on 1.0.0b2.
- **106 defects (P0 4, P1 15, P2 47, P3 40):** `docs/QA-LOG.md`.
- **Coverage table:** `docs/QA-LOG.md`.
- **41–85 ms exposure gap:** `docs/TECHNICAL-REFERENCE.md`.
- **Stage 1–2 timings and the keystroke-timing table:** produced by running the
  real `probolos.rules` functions on the testbed presets and on synthetic
  observations (5000 and 1000 runs, Python 3.11, x86_64). Re-run them on your
  own machine and update Tables 6.3 and 6.4 if you like.
