\NeedsTeXFormat{LaTeX2e}

\ProvidesClass{usenixsubmit}
\LoadClass[11pt,letterpaper,onecolumn]{article}
\usepackage{times}
\usepackage[margin=1in]{geometry}

% Usenix margins
% Gives active areas of 6.5" x 9.0"
%

\setlength{\textheight}{9.0in}
\setlength{\textwidth}{6.5in}
%\setlength{\footskip}{0.0in}
%\setlength{\footheight}{0.0in}
\setlength{\topmargin}{0.0in}
\setlength{\headheight}{0.0in}
\setlength{\headsep}{0.0in}
\setlength{\marginparsep}{1.5em}
\setlength{\marginparwidth}{0.35in}

%
% The author section
% should have names in Roman, address in
% italic, e-mail/http in typewriter.
% This is enforced by use of these macros
%
\def\authname#1{{#1}\\}
\def\authaddr#1{\itshape{#1}\\}
\def\authurl#1{{\normalsize #1}\\}
