should_apply_risk() {
    local risk_level="$1"
    case "$RISK_LEVEL" in
        "all") return 0 ;;
        "low")     [[ "$risk_level" == "low" ]] && return 0 ;;
        "medium")  [[ "$risk_level" == "medium" ]] && return 0 ;;
        "high")    [[ "$risk_level" == "high" ]] && return 0 ;;
        "critical")[[ "$risk_level" == "critical" ]] && return 0 ;;
    esac
    return 1
}
