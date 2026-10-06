FROM mcr.microsoft.com/playwright:v1.63.0-noble
WORKDIR /opt/pveil-verifier
RUN npm install --omit=dev --ignore-scripts --no-audit --no-fund playwright@1.63.0
COPY worker.mjs ./worker.mjs
LABEL org.phantomveil.verifier="1.63.0"
USER pwuser
ENTRYPOINT ["node", "/opt/pveil-verifier/worker.mjs"]
