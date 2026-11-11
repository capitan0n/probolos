# Build the thesis PDF with XeLaTeX + Biber.
#   make        -> main.pdf
#   make watch  -> rebuild on every save
#   make clean  -> remove build artefacts
main.pdf: $(wildcard *.tex */*.tex) references.bib
	latexmk -xelatex -interaction=nonstopmode main.tex

watch:
	latexmk -xelatex -pvc -interaction=nonstopmode main.tex

clean:
	latexmk -C main.tex

.PHONY: watch clean
