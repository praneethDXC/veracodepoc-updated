package com.veracode.verademo.commands;
 
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
 
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
 
public class ListenCommand implements BlabberCommand {
    private static final Logger logger = LogManager.getLogger("VeraDemo:ListenCommand");
 
    private Connection connect;
 
    private String username;
 
    public ListenCommand(Connection connect, String username) {
        super();
        this.connect = connect;
        this.username = username;
    }
 
    @Override
    public void execute(String blabberUsername) {
        String sqlQuery = "INSERT INTO listeners (blabber, listener, status) values (?, ?, 'Active');";
        logger.info(sqlQuery);
        PreparedStatement action;
        try {
            action = connect.prepareStatement(sqlQuery);
 
            action.setString(1, blabberUsername);
            action.setString(2, username);
            action.execute();
 
            sqlQuery = "SELECT blab_name FROM users WHERE username = ?";
            PreparedStatement sqlStatement = connect.prepareStatement(sqlQuery);
            sqlStatement.setString(1, blabberUsername);
            logger.info(sqlStatement.toString());
            ResultSet result = sqlStatement.executeQuery();
            result.next();
 
            String event = username + " started listening to " + blabberUsername + " (" + result.getString(1) + ")";
            sqlQuery = "INSERT INTO users_history (blabber, event) VALUES (?, ?)";
            PreparedStatement historyStatement = connect.prepareStatement(sqlQuery);
            historyStatement.setString(1, username);
            historyStatement.setString(2, event);
            logger.info(historyStatement.toString());
            historyStatement.execute();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
 
}