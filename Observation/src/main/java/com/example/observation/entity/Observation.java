package com.example.observation.entity;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

@Document("observation")
@Data
public class Observation {

    @Id
    private String id;
    private Integer notation;
    private String comment;
    private Long idDriver;
    private Long idClient;
    private Long idReservation;

    public Observation(String id, Integer notation, String comment,Long idDriver, Long idClient, Long idReservation) {
        this.id = id;
        this.notation = notation;
        this.comment = comment;
        this.idClient = idClient;
        this.idDriver = idDriver;
        this.idReservation = idReservation;
    }


}
