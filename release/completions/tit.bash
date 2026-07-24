_tit()
{
    local cur prev commands
    COMPREPLY=()
    cur=${COMP_WORDS[COMP_CWORD]}
    prev=${COMP_WORDS[COMP_CWORD-1]}
    commands="serve invite-code doctor inspect dump repair maintenance backup restore setup admin help"

    case "$prev" in
        --config|--backup|backup|restore)
            COMPREPLY=( $(compgen -f -- "$cur") )
            return
            ;;
        --public-url|--http-listen|--ssh-listen|--ssh-public-host|--ssh-public-port)
            return
            ;;
        --retention-days)
            return
            ;;
    esac

    if [[ "$cur" == -* ]]; then
        COMPREPLY=( $(compgen -W "--config --user --public-url --http-listen --ssh-listen --ssh-public-host --ssh-public-port --help --version" -- "$cur") )
    elif [ "$COMP_CWORD" -eq 1 ]; then
        COMPREPLY=( $(compgen -W "$commands" -- "$cur") )
    fi
}
complete -F _tit tit
