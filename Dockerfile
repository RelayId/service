FROM golang:1.27.2 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /relay ./src

FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=build /relay /relay
EXPOSE 3000
USER nonroot:nonroot
ENTRYPOINT ["/relay"]
