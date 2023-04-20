# Build stage

FROM golang:1.19-alpine AS build

RUN apk --no-cache add git

WORKDIR /app

COPY . .

RUN CGO_ENABLED=0 go build -o /app/bin/app

# Final stage
FROM gcr.io/distroless/static
COPY --from=build /app/bin/app /
CMD ["/app"]