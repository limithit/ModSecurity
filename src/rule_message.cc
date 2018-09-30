/*
 * ModSecurity, http://www.modsecurity.org/
 * Copyright (c) 2015 Trustwave Holdings, Inc. (http://www.trustwave.com/)
 *
 * You may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * If any of the files related to licensing are missing or if you have any
 * other questions related to licensing please contact Trustwave Holdings, Inc.
 * directly using the email address security@modsecurity.org.
 *
 */

#include "modsecurity/rules.h"

#include "modsecurity/rule_message.h"

#include "modsecurity/modsecurity.h"
#include "modsecurity/transaction.h"
#include "src/utils/string.h"
#include <mysql.h>
#include <stdio.h>

namespace modsecurity {


std::string RuleMessage::_details(const RuleMessage *rm) {
    std::string msg;
    /*************/
       MYSQL *conn_ptr;
       MYSQL_RES *res_ptr;
       MYSQL_ROW sqlrow;
       conn_ptr = mysql_init(NULL);
       if(mysql_real_connect(conn_ptr, "127.0.0.1", "root", "root",
                                                        "audit_sec", 0, NULL, 0)){
                    char value = 1;
                    mysql_options(conn_ptr, MYSQL_OPT_RECONNECT, &value);
           char update_mod[512];
                    sprintf(update_mod, "update modsecurity set mod_id=1, clientip='%s', SecRule_id='%s', attack_type='%s' where mod_id=0", std::string(rm->m_serverIpAddress).c_str(), std::to_string(rm->m_ruleId).c_str(),  rm->m_message.c_str());
                            mysql_query(conn_ptr, update_mod);
       }
       mysql_free_result(res_ptr);
       mysql_close(conn_ptr);
  

    /************/
    msg.append(" [file \"" + std::string(rm->m_ruleFile) + "\"]");
    msg.append(" [line \"" + std::to_string(rm->m_ruleLine) + "\"]");
    msg.append(" [id \"" + std::to_string(rm->m_ruleId) + "\"]");
    msg.append(" [rev \"" + rm->m_rev + "\"]");
    msg.append(" [msg \"" + rm->m_message + "\"]");
    msg.append(" [data \"" + rm->m_data + "\"]");
    msg.append(" [severity \"" +
        std::to_string(rm->m_severity) + "\"]");
    msg.append(" [ver \"" + rm->m_ver + "\"]");
    msg.append(" [maturity \"" + std::to_string(rm->m_maturity) + "\"]");
    msg.append(" [accuracy \"" + std::to_string(rm->m_accuracy) + "\"]");
    for (auto &a : rm->m_tags) {
        msg.append(" [tag \"" + a + "\"]");
    }
    msg.append(" [hostname \"" + std::string(rm->m_serverIpAddress) \
        + "\"]");
    msg.append(" [uri \"" + rm->m_uriNoQueryStringDecoded + "\"]");
    msg.append(" [unique_id \"" + rm->m_id + "\"]");
    msg.append(" [ref \"" + rm->m_reference + "\"]");

    return msg;
}


std::string RuleMessage::_errorLogTail(const RuleMessage *rm) {
    std::string msg;

    msg.append("[hostname \"" + std::string(rm->m_serverIpAddress) + "\"]");
    msg.append(" [uri \"" + rm->m_uriNoQueryStringDecoded + "\"]");
    msg.append(" [unique_id \"" + rm->m_id + "\"]");

    return msg;
}


std::string RuleMessage::log(const RuleMessage *rm, int props, int code) {
    std::string msg("");

    if (props & ClientLogMessageInfo) {
        msg.append("[client " + std::string(rm->m_clientIpAddress) + "] ");
    }

    if (rm->m_isDisruptive) {
        msg.append("ModSecurity: Access denied with code ");
        if (code == -1) {
            msg.append("%d");
        } else {
            msg.append(std::to_string(code));
        }
        msg.append(" (phase ");
        msg.append(std::to_string(rm->m_rule->m_phase - 1) + "). ");
    } else {
        msg.append("ModSecurity: Warning. ");
    }

    msg.append(rm->m_match);
    msg.append(_details(rm));

    if (props & ErrorLogTailLogMessageInfo) {
        msg.append(" " + _errorLogTail(rm));
    }

    return modsecurity::utils::string::toHexIfNeeded(msg);
}


}  // namespace modsecurity
