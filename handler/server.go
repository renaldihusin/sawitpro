package handler

import "github.com/renaldihusin/sawitpro/repository"

//go:generate mockgen -source=./server.go -destination=./server_mock.go -package=handler

type Server struct {
	Repository repository.RepositoryInterface
}

type NewServerOptions struct {
	Repository repository.RepositoryInterface
}

func NewServer(opts NewServerOptions) *Server {
	return &Server{
		Repository: opts.Repository,
	}
}
